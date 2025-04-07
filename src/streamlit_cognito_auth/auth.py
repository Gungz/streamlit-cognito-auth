from typing import Dict, Any, Type, TypeVar, Optional, Tuple, List
import time
from abc import ABC, abstractmethod
import boto3
import botocore.client
import base64
import requests
import logging

import streamlit as st

from .exceptions import TokenVerificationException
from .utils import verify_access_token

import pycognito # type: ignore
from pycognito import AWSSRP

from pydantic import BaseModel, Field, ValidationError, Extra, parse_obj_as

logger = logging.getLogger(__name__)

CR = TypeVar('CR', bound='Credentials')

class Credentials(BaseModel, extra=Extra.allow):
    """Temporary AWS Cognito credentials."""

    id_token: str = Field(..., min_length=1)
    access_token: str = Field(..., min_length=1)
    refresh_token: str = Field(..., min_length=1)
    expires_in: int
    token_type: str = Field(..., min_length=1)

    @classmethod
    def from_tokens(cls: Type[CR], tokens: Dict[str, Any]) -> CR:
        """Creates credentials from AWSSRP authentication response."""
        res = tokens["AuthenticationResult"]
        return cls(
            id_token=res["IdToken"],
            access_token=res["AccessToken"],
            refresh_token=res["RefreshToken"],
            expires_in=res["ExpiresIn"],
            token_type=res["TokenType"],
        )


class CognitoAuthSessionStateManager:
    """Saves and loads authorization credentials to streamlit session state."""

    def __init__(self) -> None:
        def init_state(name, default_value: Any=""):
            if not name in st.session_state: st.session_state[name] = default_value
        init_state("auth_id_token")
        init_state("auth_access_token")
        init_state("auth_refresh_token")
        init_state("auth_expires_in")
        init_state("auth_token_type")
        init_state("auth_state")
        init_state("auth_username")
        init_state("auth_reset_password_session")
        init_state("auth_reset_password_username")
        init_state("auth_reset_password_password")
        init_state("auth_mfa_required")
        init_state("auth_mfa_session")
        init_state("auth_mfa_type")
        init_state("auth_mfa_setup_session")
    
    def set_mfa_challenge(self, session: str, mfa_type: str) -> None:
        """Sets the MFA challenge session in streamlit session state."""
        st.session_state["auth_mfa_required"] = True
        st.session_state["auth_mfa_session"] = session
        st.session_state["auth_mfa_type"] = mfa_type

    def clear_mfa_challenge(self) -> None:
        """Clears the MFA challenge from streamlit session state."""
        st.session_state["auth_mfa_required"] = False
        st.session_state["auth_mfa_session"] = ""
        st.session_state["auth_mfa_type"] = ""

    def is_mfa_required(self) -> bool:
        """Returns if MFA challenge is required."""
        return st.session_state["auth_mfa_required"]

    def get_mfa_session(self) -> Optional[str]:
        """Returns the MFA session if exists."""
        return st.session_state.get("auth_mfa_session")

    def get_mfa_type(self) -> Optional[str]:
        """Returns the MFA type if exists."""
        return st.session_state.get("auth_mfa_type")

    def set_credentials(self, credentials: Credentials) -> None:
        """Saves the credentials to streamlit session state."""
        st.session_state["auth_id_token"] = credentials.id_token
        st.session_state["auth_access_token"] = credentials.access_token
        st.session_state["auth_refresh_token"] = credentials.refresh_token
        st.session_state["auth_expires_in"] = credentials.expires_in
        st.session_state["auth_token_type"] = credentials.token_type

    def reset_credentials(self) -> None:
        """Clears the credentials from streamlit session state."""
        st.session_state["auth_id_token"] = ""
        st.session_state["auth_access_token"] = ""
        st.session_state["auth_refresh_token"] = ""
        st.session_state["auth_expires_in"] = 0
        st.session_state["auth_token_type"] = ""

    def load_credentials(self) -> Optional[Credentials]:
        """Loads the credentials from streamlit session state.

        Returns None if no credentials were found."""
        try:
            return Credentials(
                id_token=st.session_state["auth_id_token"],
                access_token=st.session_state["auth_access_token"],
                refresh_token=st.session_state["auth_refresh_token"],
                expires_in=st.session_state["auth_expires_in"],
                token_type=st.session_state["auth_token_type"],
            )
        except ValidationError:
            return None

    def set_logged_in(self, username: Optional[str], email: Optional[str]) -> None:
        """Sets the logged in flag and the username in streamlit session state."""
        st.session_state["auth_state"] = "logged_in"
        st.session_state["auth_username"] = username
        st.session_state["auth_email"] = email

    def set_logged_out(self) -> None:
        """Clears the logged in flag from streamlit session state."""
        st.session_state["auth_state"] = "logged_out"
        st.session_state["auth_username"] = ""

    def is_logged_in(self) -> bool:
        """Returns if the user is currently logged in as of the streamlit session state."""
        return st.session_state["auth_state"] == "logged_in"

    def get_username(self) -> Optional[str]:
        """Returns the username saved in streamlit session state."""
        return st.session_state.get("auth_username") or None

    def get_email(self) -> Optional[str]:
        """Returns the email saved in streamlit session state."""
        return st.session_state.get("auth_email") or None

    def set_reset_password_session(self,
        reset_password_username: str,
        reset_password_password: str,
        reset_password_session: str = "reset_password",
    ) -> None:
        """Sets the password reset session to streamlit session state."""
        st.session_state["auth_reset_password_session"] = reset_password_session
        st.session_state["auth_reset_password_username"] = reset_password_username
        st.session_state["auth_reset_password_password"] = reset_password_password

    def clear_reset_password_session(self) -> None:
        """Clears the password reset session from streamlit session state/"""
        st.session_state["auth_reset_password_session"] = ""
        st.session_state["auth_reset_password_username"] = ""
        st.session_state["auth_reset_password_password"] = ""

    def is_reset_password_session(self) -> bool:
        """Returns if password reset session is set in streamlit session state."""
        return bool(st.session_state["auth_reset_password_session"])

    def reset_password_credentials(self) -> Tuple[Optional[str], Optional[str]]:
        """Returns the password reset username and password saved in streamlit session state."""
        username = st.session_state["auth_reset_password_username"] or None
        password = st.session_state["auth_reset_password_password"] or None
        return (username, password)


class CognitoAuthCookieManagerBase(ABC):
    """Base class for cognito authenticator cookie managers."""

    @abstractmethod
    def set_credentials(self, credentials: Credentials) -> None:
        """Saves credentials to cookies."""

    @abstractmethod
    def load_credentials(self) -> Optional[Credentials]:
        """Loads credentials from cookies."""

    @abstractmethod
    def reset_credentials(self) -> None:
        """Clears cookie credentials."""


class CognitoAuthCookieManagerNoop(CognitoAuthCookieManagerBase):
    """Dummy cognito authenticator cookie manager to be used when the authenticator does not
    wish to save credentials to cookies."""

    def set_credentials(self, credentials: Credentials) -> None:
        pass

    def load_credentials(self) -> Optional[Credentials]:
        return None

    def reset_credentials(self) -> None:
        pass


class CognitoAuthCookieManager(CognitoAuthCookieManagerBase):
    """Cognito authenticator cookie manager that saves credentials to browser cookies."""

    def __init__(self) -> None:
        try:
            import extra_streamlit_components as stx # type: ignore
        except ImportError:
            raise RuntimeError(
                "To use cookies you must install `pip install extra-streamlit-components`"
            )
        self.cookie_manager = stx.CookieManager()

    def set_credentials(self, credentials: Credentials) -> None:
        self.cookie_manager.set("id_token", credentials.id_token, key="set_id_token")
        self.cookie_manager.set("access_token", credentials.access_token, key="set_access_token")
        self.cookie_manager.set("refresh_token", credentials.refresh_token, key="set_refresh_token")
        self.cookie_manager.set("expires_in", credentials.expires_in, key="set_expires_in")
        self.cookie_manager.set("token_type", credentials.token_type, key="set_token_type")

    def load_credentials(self) -> Optional[Credentials]:
        cookies = self.cookie_manager.get_all("load_credentials_get_all")
        time.sleep(0.3)
        try:
            return Credentials(**cookies)
        except ValidationError:
            return None

    def reset_credentials(self) -> None:
        def delete_cookie(name: str) -> None:
            key = "delete_" + name
            if key in st.session_state:
                return
            try:
                self.cookie_manager.delete(name, key=key)
                logger.info(f"deleted cookie: {name}")
            except KeyError:
                logger.warning(f"Requested to delete non existing cookie: {name}")
        logger.info("reset_credentials start")
        delete_cookie("id_token")
        delete_cookie("access_token")
        delete_cookie("refresh_token")
        delete_cookie("expires_in")
        delete_cookie("token_type")
        logger.info("reset_credentials end")


class CognitoAuthenticatorBase(ABC):
    """Base class for cognito base authenticators.

    Args:
        pool_id: Cognito pool ID.
        app_client_id: Cognito Application client ID.
        app_client_secret: Cognito Application client secret.
        boto_client: optional boto3 CognitoIdentityProvider ("cognito-idp") client
        use_cookies: use cookies to save credentials.
    """

    def __init__(
        self,
        pool_id: str,
        app_client_id: str,
        app_client_secret: Optional[str]=None,
        boto_client: Optional[Any]=None,
        use_cookies: bool=True,
        app_name: str="Cognito"
    ):
        self.pool_region = pool_id.split("_")[0]
        self.client = boto_client or boto3.client(
            "cognito-idp", region_name=self.pool_region
        )
        self.pool_id = pool_id
        self.app_client_id = app_client_id
        self.app_client_secret = app_client_secret
        self.app_name = app_name

        self.session_manager = CognitoAuthSessionStateManager()
        self.cookie_manager = (
            CognitoAuthCookieManager() if use_cookies else CognitoAuthCookieManagerNoop()
        )

    def _login_from_cookies(self) -> bool:
        credentials = self.cookie_manager.load_credentials()
        logged_in = False
        if credentials:
            logger.info("Found credentials in cookies, trying to log in ...")
            logged_in = self._set_state_login(credentials=credentials)
        if not logged_in:
            logger.info("Clearing cookie credentials")
            self.cookie_manager.reset_credentials()
        return logged_in

    def _set_state_login(self, credentials: Credentials) -> bool:
        try:
            claims, user = verify_access_token(
                self.pool_id,
                self.app_client_id,
                self.pool_region,
                credentials.access_token
            )
        except TokenVerificationException as exc:
            logger.exception(exc)
            claims = None
        if claims:
            self.session_manager.set_credentials(credentials=credentials)
            try:
                email = user.email
            except AttributeError:
                email = None
            self.session_manager.set_logged_in(username=claims["username"], email=email)
            self.cookie_manager.set_credentials(credentials=credentials)
            logger.info("Successfully logged in")
            return True
        else:
            logger.info("Could not log in")
            self._set_state_logout()
            return False

    def _set_state_logout(self) -> None:
        self.session_manager.reset_credentials()
        self.session_manager.set_logged_out()

    def _login_from_saved_credentials(self) -> bool:
        logged_in = False
        logger.info("_login_from_saved_credentials")
        session_state_credentials = self.session_manager.load_credentials()
        if session_state_credentials:
            logged_in = self._set_state_login(credentials=session_state_credentials)
            logger.info(f"Logged in with session state credentials: {logged_in}")
        else:
            logger.info(f"No credentials in session state")
        if not logged_in:
            logger.info(f"Logging in from cookies")
            logged_in = self._login_from_cookies()
            logger.info(f"Logged in with cookies credentials: {logged_in}")
        logger.info("_login_from_saved_credentials finished")
        return logged_in

    @abstractmethod
    def login(self) -> bool:
        """Logs in the user, showing UI elements if necessary.

        Returns: True if the user was successfully logged in.
        """

    def logout(self):
        """Logs out the currently logged user."""
        logger.info("Logout")
        self._set_state_logout()
        self.cookie_manager.reset_credentials()

    def is_logged_in(self) -> bool:
        """Returns wether the current user is logged in."""
        return self.session_manager.is_logged_in()

    def get_username(self) -> Optional[str]:
        """Gets the user name of the current user, if he is logged in."""
        return self.session_manager.get_username()

    def get_email(self) -> Optional[str]:
        """Gets the email of the current user, if he is logged in."""
        return self.session_manager.get_email()

    def get_credentials(self) -> Optional[Credentials]:
        return self.session_manager.load_credentials()

class CognitoAuthenticator(CognitoAuthenticatorBase):
    """Authenticates the user with Cognito using custom streamlit UI elements."""

    def _secret_hash(self, username: str) -> str:
        """Calculate the secret hash for Cognito authentication."""
        import hmac
        import base64
        import hashlib
        
        message = username + self.app_client_id
        dig = hmac.new(
            key=self.app_client_secret.encode('UTF-8'),
            msg=message.encode('UTF-8'),
            digestmod=hashlib.sha256
        ).digest()
        
        return base64.b64encode(dig).decode()

    def _handle_mfa_setup_challenge(self, username: str, session: str) -> bool:
        """Handle MFA setup challenge by associating a TOTP token."""
        try:
            # Add parameters for associate_software_token if client secret exists
            params = {"Session": session}

            # Start TOTP setup
            response = self.client.associate_software_token(**params)
            
            secret_code = response.get("SecretCode")
            new_session = response.get("Session")
            
            # Store necessary information in session state
            st.session_state["auth_username"] = username
            st.session_state["auth_mfa_setup_session"] = new_session
            st.session_state["auth_mfa_secret"] = secret_code
            
            return True
        except Exception as e:
            logger.exception(f"Error setting up MFA: {e}")
            return False

    def _verify_mfa_setup(self, username: str, session: str, verification_code: str) -> bool:
        """Verify the MFA setup with the provided code."""
        try:
            response = self.client.verify_software_token(
                Session=session,
                UserCode=verification_code
            )
            
            if response.get("Status") == "SUCCESS":
                # Prepare challenge responses with SECRET_HASH if client secret exists
                challenge_responses = {
                    "USERNAME": username,
                    "SESSION": response.get("Session")
                }

                # Add SECRET_HASH if client secret is configured
                if self.app_client_secret is not None:
                    challenge_responses["SECRET_HASH"] = self._secret_hash(username)

                # After successful verification, we need to respond to the original MFA_SETUP challenge
                challenge_response = self.client.respond_to_auth_challenge(
                    ClientId=self.app_client_id,
                    ChallengeName="MFA_SETUP",
                    Session=response.get("Session"),
                    ChallengeResponses=challenge_responses
                )
                
                # Check if we got tokens back
                auth_result = challenge_response.get("AuthenticationResult")
                if auth_result:
                    credentials = Credentials(
                        id_token=auth_result["IdToken"],
                        access_token=auth_result["AccessToken"],
                        refresh_token=auth_result["RefreshToken"],
                        expires_in=auth_result["ExpiresIn"],
                        token_type=auth_result["TokenType"]
                    )
                    return self._set_state_login(credentials=credentials)
                
            return False
        except Exception as e:
            logger.exception(f"Error verifying MFA setup: {e}")
            return False

    def _show_mfa_setup_form(self, placeholder):
        """Show MFA setup form with QR code."""
        with placeholder:
            cols = st.columns([1, 3, 1])
            with cols[1]:
                st.subheader("MFA Setup Required")
                
                # Get the secret code from session state
                secret_code = st.session_state.get("auth_mfa_secret")
                
                if secret_code:
                    st.write("1. Scan this QR code with your authenticator app:")
                    
                    # Generate QR code
                    import qrcode
                    import io
                    from base64 import b64encode
                    
                    totp_uri = f"otpauth://totp/{st.session_state.get('auth_username')}?secret={secret_code}&issuer={self.app_name}"
                    qr = qrcode.QRCode(version=1, box_size=10, border=5)
                    qr.add_data(totp_uri)
                    qr.make(fit=True)
                    
                    img = qr.make_image(fill_color="black", back_color="white")
                    buffered = io.BytesIO()
                    img.save(buffered, format="PNG")
                    img_str = b64encode(buffered.getvalue()).decode()
                    
                    st.markdown(f'<img src="data:image/png;base64,{img_str}" alt="QR Code">', unsafe_allow_html=True)
                    
                    # Manual entry option
                    with st.expander("Can't scan the QR code?"):
                        st.code(secret_code)
                        st.write("Enter this code manually in your authenticator app")
                    
                    st.write("2. Enter the code from your authenticator app:")
                    
                    with st.form("mfa_setup_form"):
                        verification_code = st.text_input("Verification Code", key="mfa_setup_code")
                        submitted = st.form_submit_button("Verify")
                        
                    return submitted, verification_code
                else:
                    st.error("Error getting MFA setup information")
                    return False, None

    def _show_login_form(self, placeholder):
        with placeholder:
            cols = st.columns([1, 3, 1])
            with cols[1]:
                with st.form("login_form"):
                    st.subheader("Login")
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    login_submitted = st.form_submit_button("Login")
                    status_container = st.container()

        return login_submitted, username, password, status_container

    def _show_password_reset_form(self, placeholder):
        username, password = self.session_manager.reset_password_credentials()
        with placeholder:
            cols = st.columns([1, 3, 1])
            with cols[1]:
                with st.form("reset_password_form"):
                    st.subheader("Reset Password")
                    username = st.text_input(
                        "Username",
                        value=username,
                    )
                    password = st.text_input(
                        "Password",
                        type="password",
                        value=password,
                        disabled=True,
                    )
                    new_password = st.text_input("New Password", type="password")
                    confirm_new_password = st.text_input(
                        "Confirm Password", type="password"
                    )
                    password_reset_submitted = st.form_submit_button("Reset Password")
                    status_container = st.container()

        return (
            password_reset_submitted,
            username,
            password,
            new_password,
            confirm_new_password,
            status_container,
        )

    def _login(self, username, password):
        aws_srp_args = {
            "client": self.client,
            "pool_id": self.pool_id,
            "client_id": self.app_client_id,
            "username": username,
            "password": password,
        }

        if self.app_client_secret is not None:
            aws_srp_args["client_secret"] = self.app_client_secret

        aws_srp = AWSSRP(**aws_srp_args)

        try:
            tokens = aws_srp.authenticate_user()

        except self.client.exceptions.SoftwareTokenMFANotFoundException as e:
            # TOTP MFA not set up
            logger.info("TOTP MFA not set up")
            self._set_state_logout()
            return False

        except self.client.exceptions.CodeMismatchException as e:
            # Invalid MFA code
            logger.info("Invalid MFA code")
            self._set_state_logout()
            return False

        except pycognito.exceptions.ForceChangePasswordException as e:
            logger.info("Force password reset")
            self._set_reset_password_session(username, password)
            return False

        except self.client.exceptions.PasswordResetRequiredException as e:
            logger.info("Password reset required")
            self._set_state_logout()
            return False

        except self.client.exceptions.NotAuthorizedException as e:
            logger.info("Login not authorized")
            self._set_state_logout()
            return False
        
        except self.client.exceptions.UserNotConfirmedException as e:
            logger.info("User not confirmed")
            self._set_state_logout()
            return False
    
        except pycognito.exceptions.MFAChallengeException as mfa_challenge:
            # Handle MFA challenge
            mfa_tokens = mfa_challenge.get_tokens()
            challenge = mfa_tokens.get("ChallengeName")
            session = mfa_tokens.get("Session")
            
            # Store username for the MFA challenge
            st.session_state["auth_username"] = username
            
            if challenge == "SMS_MFA":
                self.session_manager.set_mfa_challenge(session, "SMS")
                return False
            elif challenge == "SOFTWARE_TOKEN_MFA":
                self.session_manager.set_mfa_challenge(session, "TOTP")
                return False
            else:
                logger.error(f"Unsupported challenge: {challenge}")
                self._set_state_logout()
                return False
        
    
        except Exception as e:
            logger.exception(f"Unknown exception during login: {e}")
            self._set_state_logout()
            raise e

        else:
            #print(tokens)
            
            # Check if we got tokens (no MFA) or challenge (MFA required)
            if "AuthenticationResult" in tokens:
                # No MFA required
                credentials = Credentials.from_tokens(tokens)
                return self._set_state_login(credentials=credentials)
            elif "ChallengeName" in tokens:
                # Handle MFA challenge
                challenge = tokens.get("ChallengeName")
                session = tokens.get("Session")
                
                # Store username for the MFA challenge
                st.session_state["auth_username"] = username
                
                if challenge == "MFA_SETUP":
                    # Handle MFA setup challenge
                    logger.info("MFA setup required")
                    if self._handle_mfa_setup_challenge(username, session):
                        self.session_manager.set_mfa_challenge(session, "SETUP")
                        return False
                    else:
                        logger.error("Failed to initiate MFA setup")
                        self._set_state_logout()
                        return False
                elif challenge == "SMS_MFA":
                    self.session_manager.set_mfa_challenge(session, "SMS")
                    return False
                elif challenge == "SOFTWARE_TOKEN_MFA":
                    self.session_manager.set_mfa_challenge(session, "TOTP")
                    return False
                else:
                    logger.error(f"Unsupported challenge: {challenge}")
                    self._set_state_logout()
                    return False
            else:
                logger.error("Unexpected authentication response")
                self._set_state_logout()
                return False
        
    def _respond_to_mfa_challenge(self, username: str, code: str, session: str, mfa_type: str) -> bool:
        try:
            challenge_responses = {
                "USERNAME": username,
                "SMS_MFA_CODE": code if mfa_type == "SMS" else None,
                "SOFTWARE_TOKEN_MFA_CODE": code if mfa_type == "TOTP" else None,
            }
            # Remove None values
            challenge_responses = {k: v for k, v in challenge_responses.items() if v is not None}

            if self.app_client_secret is not None:
                challenge_responses["SECRET_HASH"] = self._secret_hash(username)

            response = self.client.respond_to_auth_challenge(
                ClientId=self.app_client_id,
                ChallengeName="SMS_MFA" if mfa_type == "SMS" else "SOFTWARE_TOKEN_MFA",
                Session=session,
                ChallengeResponses=challenge_responses
            )
            tokens = response.get("AuthenticationResult")
            if tokens:
                credentials = Credentials(
                    id_token=tokens["IdToken"],
                    access_token=tokens["AccessToken"],
                    refresh_token=tokens["RefreshToken"],
                    expires_in=tokens["ExpiresIn"],
                    token_type=tokens["TokenType"]
                )
                return self._set_state_login(credentials=credentials)
            return False
        except self.client.exceptions.CodeMismatchException:
            logger.info("Invalid MFA code")
            return False
        except Exception as e:
            logger.exception(f"Error responding to MFA challenge: {e}")
            return False

    def _set_reset_password_session(self,
        reset_password_username: str, reset_password_password: str
    ) -> None:
        logger.info("Set password reset state")
        self.session_manager.set_reset_password_session(
            reset_password_username, reset_password_password
        )

    def _reset_password(self, username, password, new_password) -> bool:
        aws_srp_args = {
            "client": self.client,
            "pool_id": self.pool_id,
            "client_id": self.app_client_id,
            "username": username,
            "password": password,
        }

        if self.app_client_secret is not None:
            aws_srp_args["client_secret"] = self.app_client_secret

        aws_srp = AWSSRP(**aws_srp_args)

        try:
            tokens = aws_srp.set_new_password_challenge(new_password=new_password)

        except self.client.exceptions.NotAuthorizedException as e:
            logger.info("Password reset not authorized")
            self._set_state_logout()
            return False

        except Exception as e:
            logger.exception(f"Unknown exception during password reset: {e}")
            self._set_state_logout()
            raise e

        else:

            if "AuthenticationResult" in tokens:
                # No MFA required
                credentials = Credentials.from_tokens(tokens)
                logged_in = self._set_state_login(credentials=credentials)
                if logged_in:
                    self.session_manager.clear_reset_password_session()
                return logged_in
            elif "ChallengeName" in tokens:
                # Handle MFA challenge
                challenge = tokens.get("ChallengeName")
                session = tokens.get("Session")
                
                # Store username for the MFA challenge
                st.session_state["auth_username"] = username
                
                if challenge == "MFA_SETUP":
                    # Handle MFA setup challenge
                    logger.info("MFA setup required")
                    if self._handle_mfa_setup_challenge(username, session):
                        self.session_manager.clear_reset_password_session()
                        self.session_manager.set_mfa_challenge(session, "SETUP")
                        return True
                    else:
                        logger.error("Failed to initiate MFA setup")
                        self._set_state_logout()
                        return False
                else:
                    logger.error(f"Unsupported challenge: {challenge}")
                    self._set_state_logout()
                    return False
            else:
                logger.error("Unexpected authentication response")
                self._set_state_logout()
                return False
            
            #credentials = Credentials.from_tokens(tokens)
            #logged_in = self._set_state_login(credentials=credentials)
            #if logged_in:
            #    self.session_manager.clear_reset_password_session()
            #return logged_in
    
    def _show_mfa_form(self, placeholder):
        with placeholder:
            cols = st.columns([1, 3, 1])
            with cols[1]:
                with st.form("mfa_form"):
                    st.subheader("Enter MFA Code")
                    mfa_type = self.session_manager.get_mfa_type()
                    st.text(f"Enter the {'SMS' if mfa_type == 'SMS' else 'authenticator app'} code")
                    code = st.text_input("Code")
                    mfa_submitted = st.form_submit_button("Verify")
                    status_container = st.container()
        return mfa_submitted, code, status_container


    def login(self) -> bool:
        form_placeholder = st.empty()

        # Check if MFA is required
        if self.session_manager.is_mfa_required():
            mfa_type = self.session_manager.get_mfa_type()
        
            if mfa_type == "SETUP":
                # Handle MFA setup flow
                submitted, verification_code = self._show_mfa_setup_form(form_placeholder)
                if not submitted:
                    return False

                username = st.session_state.get("auth_username")
                session = st.session_state.get("auth_mfa_setup_session")

                if not all([username, session, verification_code]):
                    st.error("Missing MFA setup information")
                    return False

                if self._verify_mfa_setup(username, session, verification_code):
                    self.session_manager.clear_mfa_challenge()
                    st.success("MFA setup completed")
                    st.rerun()
                else:
                    st.error("Invalid verification code")
                    return False
            else:
                # Handle regular MFA verification
                mfa_submitted, code, status_container = self._show_mfa_form(form_placeholder)
                if not mfa_submitted:
                    return False

                username = self.session_manager.get_username()
                session = self.session_manager.get_mfa_session()

                if not all([username, session, mfa_type, code]):
                    status_container.error("Missing MFA information")
                    return False

                is_mfa_valid = self._respond_to_mfa_challenge(
                    username=username,
                    code=code,
                    session=session,
                    mfa_type=mfa_type
                )

                if not is_mfa_valid:
                    status_container.error("Invalid MFA code")
                    return False

                self.session_manager.clear_mfa_challenge()
                status_container.success("Logged in")
                st.rerun()

        if self.session_manager.is_reset_password_session():
            logger.info("Password reset is requested")
            (
                password_reset_submitted,
                username,
                password,
                new_password,
                confirm_new_password,
                status_container,
            ) = self._show_password_reset_form(form_placeholder)
            if not password_reset_submitted:
                return False

            if not new_password:
                status_container.error("New password is empty")
                return False

            if new_password != confirm_new_password:
                status_container.error("New password mismatch")
                return False

            is_password_reset = self._reset_password(
                username=username,
                password=password,
                new_password=new_password,
            )
            
            if not is_password_reset:
                status_container.error("Failed to reset password")
                return False
            
            if self.session_manager.is_mfa_required():
                status_container.info("MFA Setup required")
                time.sleep(1.5)
                st.rerun()

            status_container.success("Logged in")
            st.rerun()

        logger.info("Trying to log in from saved credentials ...")
        logged_in = self._login_from_saved_credentials()
        if logged_in:
            logger.info("Success")
            return True

        logger.info("Showing login form ...")
        # login
        login_submitted, username, password, status_container = self._show_login_form(
            form_placeholder
        )
        if not login_submitted:
            logger.info("Login button was not pushed yet")
            return False

        is_logged_in = self._login(
            username=username,
            password=password,
        )
        logger.info(f"_login was called, result: {is_logged_in}")

        if self.session_manager.is_reset_password_session():
            status_container.info("Password reset is required")
            time.sleep(1.5)
            st.rerun()

        if self.session_manager.is_mfa_required():
            status_container.info("MFA required")
            time.sleep(1.5)
            st.rerun()
        elif not is_logged_in:
            status_container.error("Invalid username or password")
            return False
        else:
            status_container.success("Logged in")
            st.rerun()

        # should not reach here
        # prevent other code from running
        st.stop()
    
    def setup_totp(self, username: str) -> Tuple[bool, Optional[str]]:
        """Setup TOTP for a user.
        
        Returns:
            Tuple of (success, secret_code)
            secret_code can be used to generate QR code for authenticator apps
        """
        try:
            response = self.client.associate_software_token(
                AccessToken=self.session_manager.load_credentials().access_token
            )
            secret_code = response.get("SecretCode")
            return True, secret_code
        except Exception as e:
            logger.exception(f"Error setting up TOTP: {e}")
            return False, None

    def verify_totp_setup(self, code: str) -> bool:
        """Verify TOTP setup with the provided code."""
        try:
            self.client.verify_software_token(
                AccessToken=self.session_manager.load_credentials().access_token,
                UserCode=code
            )
            return True
        except Exception as e:
            logger.exception(f"Error verifying TOTP: {e}")
            return False



class CognitoHostedUIAuthenticator(CognitoAuthenticatorBase):
    """Authenticates the user with Cognito using Cognito Hosted UI.

    Args:
        pool_id: Cognito pool ID.
        app_client_id: Cognito Application client ID.
        app_client_secret: Cognito Application client secret.
        boto_client: optional boto3 CognitoIdentityProvider ("cognito-idp") client
        use_cookies: use cookies to save credentials.
        cognito_domain: Cognito hosted UI domain.
        redirect_uri: Redirect URI of this streamlit application.
    """

    def __init__(self,
        cognito_domain: str,
        redirect_uri: str,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.domain = cognito_domain
        if not self.domain.endswith("/"):
            self.domain += "/"
        self.redirect_uri = redirect_uri
        if not self.redirect_uri.endswith("/"):
            self.redirect_uri += "/"

    def _credentials_from_auth_code(self, code: str) -> Credentials:
        token_url = f"{self.domain}oauth2/token"
        message = bytes(f"{self.app_client_id}:{self.app_client_secret}", "utf-8")
        secret_hash = base64.b64encode(message).decode()
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.app_client_id,
            "code": code,
            "redirect_uri": str(self.redirect_uri)
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {secret_hash}"
        }
        resp = requests.post(token_url, params=payload, headers=headers)

        if resp.status_code == requests.codes.bad_request:
            raise TokenVerificationException("Invalid authorization code: " + resp.text)
        else:
            resp.raise_for_status()
        res = parse_obj_as(Credentials, resp.json())
        return res

    def show_login_button(
        self,
        response_type: str = "code",
    ) -> None:
        login_url = self.login_url(response_type=response_type)
        st.link_button("Login", login_url)

    def login_url(self, response_type: str = "code") -> str:
        """Returns the hosted UI login url."""
        return (
            f"{self.domain}login?response_type={response_type}&client_id={self.app_client_id}"
            f"&redirect_uri={self.redirect_uri}"
        )

    @staticmethod
    def get_code(query_params: Dict[str, List[str]]) -> Optional[str]:
        return query_params["code"] if (
            "code" in query_params.keys()
            and len(query_params["code"]) > 0
            and query_params["code"]
        ) else None

    def login(self, show_login_button=True, **kwargs) -> bool:

        # logged in
        if self.session_manager.is_logged_in():
            return True

        query_params = st.query_params
        logged_in = False
        code = self.get_code(query_params)
        if code:
            try:
                credentials = self._credentials_from_auth_code(code=code)
            except Exception as exc:
                st.error(str(exc))
                self._set_state_logout()
            else:
                logged_in = self._set_state_login(credentials)
                st.query_params["code"] = ""
        elif show_login_button:
            self.show_login_button(**kwargs)

        return logged_in
