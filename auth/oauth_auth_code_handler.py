#!/usr/bin/env python3
"""
OAuth 2.0 Authorization Code Flow Handler for SAP Datasphere
Implements interactive authentication via browser login with local callback server
"""

import asyncio
import logging
import os
import platform
import secrets
import subprocess
import sys
import time
import webbrowser
from typing import Optional, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs

import aiohttp
from aiohttp import web
from cryptography.fernet import Fernet

from auth.oauth_handler import OAuthToken, OAuthError, TokenAcquisitionError, TokenRefreshError

logger = logging.getLogger(__name__)


class AuthCodeFlowError(OAuthError):
    """Raised when the authorization code flow fails"""
    pass


class OAuthAuthCodeHandler:
    """
    Manages OAuth 2.0 Authorization Code Flow for SAP Datasphere

    Features:
    - Interactive browser-based authentication
    - Local HTTP callback server for redirect URI
    - CSRF protection via state parameter
    - Automatic token refresh via refresh_token
    - Encrypted token storage in memory
    - Thread-safe token access
    - Configurable timeout for browser login
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        authorize_url: str,
        token_url: str,
        redirect_port: int = 8400,
        scope: Optional[str] = None,
        login_timeout: int = 120,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.redirect_port = redirect_port
        self.redirect_uri = f"http://localhost:{redirect_port}"
        self.scope = scope
        self.login_timeout = login_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Token storage with encryption
        self._encryption_key = Fernet.generate_key()
        self._cipher = Fernet(self._encryption_key)
        self._encrypted_token: Optional[bytes] = None
        self._token: Optional[OAuthToken] = None
        self._lock = asyncio.Lock()

        # Auth flow state
        self._state: Optional[str] = None
        self._auth_code: Optional[str] = None
        self._auth_event: Optional[asyncio.Event] = None
        self._auth_error: Optional[str] = None

        # Monitoring
        self._token_acquisition_count = 0
        self._token_refresh_count = 0
        self._last_error: Optional[str] = None

        logger.info(f"OAuth Auth Code handler initialized (authorize: {authorize_url})")

    async def get_token(self, force_refresh: bool = False) -> OAuthToken:
        """
        Get a valid access token, triggering browser login if needed.

        Args:
            force_refresh: Force token refresh even if not expired

        Returns:
            Valid OAuthToken

        Raises:
            TokenAcquisitionError: If token cannot be acquired
        """
        async with self._lock:
            # Return existing token if valid
            if not force_refresh and self._token and not self._token.is_expired:
                logger.debug(f"Using cached token (expires in {self._token.time_until_expiry:.0f}s)")
                return self._token

            # Try refresh if we have a refresh token
            if self._token and self._token.refresh_token:
                logger.info("Refreshing access token via refresh_token")
                try:
                    return await self._refresh_token()
                except TokenRefreshError:
                    logger.warning("Token refresh failed, starting new auth code flow")

            # Start interactive authorization code flow
            logger.info("Starting Authorization Code flow (browser login)")
            return await self._start_auth_flow()

    async def _start_auth_flow(self) -> OAuthToken:
        """
        Start the full authorization code flow:
        1. Start local callback server
        2. Open browser with authorization URL
        3. Wait for callback with authorization code
        4. Exchange code for tokens

        Returns:
            OAuthToken from code exchange

        Raises:
            AuthCodeFlowError: If the flow fails or times out
        """
        self._state = secrets.token_urlsafe(32)
        self._auth_code = None
        self._auth_error = None
        self._auth_event = asyncio.Event()

        # Build authorization URL
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": self._state,
        }
        params["scope"] = self.scope if self.scope else "openid"

        auth_url = f"{self.authorize_url}?{urlencode(params)}"
        logger.info(f"Authorization URL: {auth_url}")

        # Start local callback server
        runner = None
        try:
            app = web.Application()
            app.router.add_get("/", self._handle_callback)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "localhost", self.redirect_port)
            await site.start()
            logger.info(f"Callback server listening on http://localhost:{self.redirect_port}/callback")

            # Open browser (multiple methods for robustness in subprocess contexts)
            logger.info(f"Opening browser for authentication...")
            self._open_browser(auth_url)

            # Wait for callback with timeout
            try:
                await asyncio.wait_for(self._auth_event.wait(), timeout=self.login_timeout)
            except asyncio.TimeoutError:
                raise AuthCodeFlowError(
                    f"Browser login timed out after {self.login_timeout} seconds. "
                    "Please try again."
                )

            # Check for errors from callback
            if self._auth_error:
                raise AuthCodeFlowError(f"Authorization failed: {self._auth_error}")

            if not self._auth_code:
                raise AuthCodeFlowError("No authorization code received")

            # Exchange code for tokens
            token = await self._exchange_code(self._auth_code)
            self._store_token(token)
            self._token_acquisition_count += 1
            self._last_error = None

            logger.info(f"Authorization Code flow completed successfully (token expires in {token.expires_in}s)")
            return token

        except AuthCodeFlowError:
            raise
        except Exception as e:
            error_msg = f"Authorization Code flow failed: {str(e)}"
            logger.error(error_msg)
            self._last_error = error_msg
            raise AuthCodeFlowError(error_msg) from e
        finally:
            # Always stop the callback server
            if runner:
                await runner.cleanup()
                logger.debug("Callback server stopped")

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """
        Handle the OAuth redirect callback.

        Validates state parameter and extracts authorization code.
        """
        # Check for error response
        error = request.query.get("error")
        if error:
            error_desc = request.query.get("error_description", "Unknown error")
            self._auth_error = f"{error}: {error_desc}"
            self._auth_event.set()
            return web.Response(
                text="<html><body><h2>Authentication failed</h2>"
                     f"<p>{error_desc}</p>"
                     "<p>You can close this window.</p>"
                     "</body></html>",
                content_type="text/html",
                status=400
            )

        # Validate state parameter (CSRF protection)
        received_state = request.query.get("state")
        if received_state != self._state:
            self._auth_error = "State parameter mismatch (possible CSRF attack)"
            self._auth_event.set()
            return web.Response(
                text="<html><body><h2>Authentication failed</h2>"
                     "<p>State parameter mismatch.</p>"
                     "</body></html>",
                content_type="text/html",
                status=400
            )

        # Extract authorization code
        code = request.query.get("code")
        if not code:
            self._auth_error = "No authorization code in callback"
            self._auth_event.set()
            return web.Response(
                text="<html><body><h2>Authentication failed</h2>"
                     "<p>No authorization code received.</p>"
                     "</body></html>",
                content_type="text/html",
                status=400
            )

        self._auth_code = code
        self._auth_event.set()

        return web.Response(
            text="<html><body><h2>Authentication successful</h2>"
                 "<p>You can close this window and return to the application.</p>"
                 "<script>window.close();</script>"
                 "</body></html>",
            content_type="text/html"
        )

    @staticmethod
    def _open_browser(url: str):
        """
        Open a URL in the default browser. Uses multiple methods for robustness,
        especially when running as a subprocess (e.g. from Claude Desktop).
        """
        opened = False

        # Method 1: Windows-native os.startfile (most reliable from subprocesses)
        if platform.system() == "Windows":
            try:
                os.startfile(url)
                opened = True
                logger.info("Browser opened via os.startfile")
            except Exception as e:
                logger.warning(f"os.startfile failed: {e}")

        # Method 2: subprocess with platform-specific command
        if not opened:
            try:
                if platform.system() == "Windows":
                    subprocess.Popen(["start", url], shell=True)
                elif platform.system() == "Darwin":
                    subprocess.Popen(["open", url])
                else:
                    subprocess.Popen(["xdg-open", url])
                opened = True
                logger.info("Browser opened via subprocess")
            except Exception as e:
                logger.warning(f"subprocess open failed: {e}")

        # Method 3: webbrowser module (fallback)
        if not opened:
            try:
                webbrowser.open(url)
                opened = True
                logger.info("Browser opened via webbrowser module")
            except Exception as e:
                logger.warning(f"webbrowser.open failed: {e}")

        if not opened:
            # Last resort: print URL to stderr for manual opening
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"Please open this URL in your browser to authenticate:", file=sys.stderr)
            print(f"{url}", file=sys.stderr)
            print(f"{'='*60}\n", file=sys.stderr)

    async def _exchange_code(self, code: str) -> OAuthToken:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            code: The authorization code from the callback

        Returns:
            OAuthToken with access_token and refresh_token

        Raises:
            TokenAcquisitionError: If code exchange fails
        """
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }

        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.token_url,
                        data=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._create_token_from_response(data)
                        else:
                            error_text = await response.text()
                            error_msg = f"Code exchange failed: HTTP {response.status} - {error_text}"
                            logger.error(error_msg)
                            self._last_error = error_msg

                            if response.status >= 500 and attempt < self.max_retries - 1:
                                delay = self.retry_delay * (2 ** attempt)
                                logger.warning(f"Retrying in {delay}s... (attempt {attempt + 1}/{self.max_retries})")
                                await asyncio.sleep(delay)
                                continue

                            raise TokenAcquisitionError(error_msg)

            except aiohttp.ClientError as e:
                error_msg = f"Network error during code exchange: {str(e)}"
                logger.error(error_msg)
                self._last_error = error_msg

                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.warning(f"Retrying in {delay}s... (attempt {attempt + 1}/{self.max_retries})")
                    await asyncio.sleep(delay)
                else:
                    raise TokenAcquisitionError(error_msg) from e

        raise TokenAcquisitionError(f"Code exchange failed after {self.max_retries} attempts")

    async def _refresh_token(self) -> OAuthToken:
        """
        Refresh the access token using the refresh token.

        Returns:
            Refreshed OAuthToken

        Raises:
            TokenRefreshError: If refresh fails
        """
        if not self._token or not self._token.refresh_token:
            raise TokenRefreshError("No refresh token available")

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": self._token.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.token_url,
                    data=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        token = self._create_token_from_response(data)
                        self._store_token(token)
                        self._token_refresh_count += 1
                        self._last_error = None

                        logger.info(f"Token refreshed successfully (expires in {token.expires_in}s)")
                        return token
                    else:
                        error_text = await response.text()
                        error_msg = f"Token refresh failed: HTTP {response.status} - {error_text}"
                        logger.error(error_msg)
                        self._last_error = error_msg
                        raise TokenRefreshError(error_msg)

        except aiohttp.ClientError as e:
            error_msg = f"Network error during token refresh: {str(e)}"
            logger.error(error_msg)
            self._last_error = error_msg
            raise TokenRefreshError(error_msg) from e

    def _create_token_from_response(self, data: Dict[str, Any]) -> OAuthToken:
        """Create OAuthToken from API response"""
        return OAuthToken(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 3600),
            scope=data.get("scope"),
            refresh_token=data.get("refresh_token")
        )

    def _store_token(self, token: OAuthToken):
        """Store token with encryption"""
        self._token = token
        token_data = token.access_token.encode("utf-8")
        self._encrypted_token = self._cipher.encrypt(token_data)

    async def revoke_token(self) -> bool:
        """Clear the current token from memory"""
        async with self._lock:
            if not self._token:
                logger.warning("No token to revoke")
                return False

            self._token = None
            self._encrypted_token = None
            logger.info("Token cleared from memory")
            return True

    def get_health_status(self) -> Dict[str, Any]:
        """Get handler health status"""
        return {
            "flow_type": "authorization_code",
            "has_token": self._token is not None,
            "token_expired": self._token.is_expired if self._token else None,
            "time_until_expiry": self._token.time_until_expiry if self._token else None,
            "has_refresh_token": bool(self._token and self._token.refresh_token),
            "acquisitions": self._token_acquisition_count,
            "refreshes": self._token_refresh_count,
            "last_error": self._last_error
        }

    def __repr__(self) -> str:
        return (f"OAuthAuthCodeHandler(client_id={self.client_id[:8]}..., "
                f"authorize_url={self.authorize_url})")
