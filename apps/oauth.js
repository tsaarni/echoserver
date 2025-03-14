import { OAuthDPop, dpopStringify } from './oauthdpop.js';
import { generateCodeVerifier, generateCodeChallenge } from './oauthpkce.js';

/**
 * OAuth implements authorization code flow and refresh token flow.
 */
class OAuth {
  // Private fields

  // Configuration from caller of the library.
  #clientId;
  #redirectUri;
  #wellKnownEndpoint;
  #log;
  #usePkce = false;
  #useDpop = false;

  // Configuration from well-known endpoint.
  #authEndpoint;
  #tokenEndpoint;
  #endSessionEndpoint;

  // Access token and refresh token from authorization server.
  #accessToken;
  #refreshToken;

  // Helper for generating DPoP proof.
  // Instantiated during authorization_code grant request and used during refresh token request and resource request.
  #dpop;

  constructor(logger) {
    this.#log = logger;
  }

  useClientId(clientId) {
    this.#clientId = clientId;
    return this;
  }

  useWellKnownEndpoint(wellKnownEndpoint) {
    this.#wellKnownEndpoint = wellKnownEndpoint;
    return this;
  }

  useRedirectUri(redirectUri) {
    this.#redirectUri = redirectUri;
    return this;
  }

  usePkce(usePkce) {
    this.#usePkce = usePkce;
    return this;
  }

  useDpop(useDpop) {
    this.#useDpop = useDpop;
    return this;
  }

  /**
   * Set the request headers for authorization.
   *
   * @param {Object} request The request object to set the authorization header on.
   * @param {string} url The URL of the request.
   * @throws {Error} If the access token has not been fetched or if DPoP was enabled after the authorization code grant request.
   */
  async setAuthorizationForRequest(request, url) {
    if (!this.#accessToken) {
      throw new Error('Access token not available');
    }

    if (this.#useDpop) {
      if (!this.#dpop) {
        throw new Error('Cannot set authorization header without DPoP key pair generated during authorization_code grant request');
      }

      request.headers.Authorization = `DPoP ${this.#accessToken}`;

      // Strip query and fragment from the URL.
      const urlObj = new URL(url);
      urlObj.search = '';
      urlObj.hash = '';
      request.headers.DPoP = await this.#dpop.generateProof(request.method, urlObj.toString());
      this.#log.info('DPoP is enabled. Sending DPoP proof JWT:', dpopStringify(request.headers.DPoP));
    } else {
      // DPoP is not enabled, so just send the access token as a Bearer token.
      request.headers.Authorization = `Bearer ${this.#accessToken}`;
    }
  }


  /**
   * Refresh the access token using the refresh token.
   * @returns {Promise} A promise that resolves with the token response.
   * @throws {Error} If the refresh token is not known or the token cannot be fetched.
   */
  async refresh() {
    if (!this.#refreshToken) {
      throw new Error('Refresh token not known');
    }
    const response = await this.#fetchTokenWithRefreshToken();
    this.#log.info('Refreshed token successfully');
    this.#accessToken = response.access_token;
    this.#refreshToken = response.refresh_token;
    return response;
  }

  /**
   * loadLoginPage redirects the browser to the login page.
   */
  async loadLoginPage() {
    let authUrl = `${this.#authEndpoint}?response_type=code&client_id=${
      this.#clientId
    }&redirect_uri=${encodeURIComponent(this.#redirectUri)}&response_mode=fragment`;

    if (this.#usePkce) {
      this.#log.info('PKCE is enabled. Generating code verifier and challenge.');

      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      authUrl += `&code_challenge=${codeChallenge}&code_challenge_method=S256`;

      // Store the code verifier in localStorage for using it when fetching the token.
      localStorage.setItem('code-verifier', codeVerifier);
    }

    window.location.href = authUrl;
  }

  /**
   * logout logs out the user by revoking the refresh token.
   * @throws {Error} If the logout fails.
   */
  async logout() {
    this.#log.info(`POST ${this.#endSessionEndpoint}`);
    const response = await fetch(this.#endSessionEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: this.#clientId,
        refresh_token: this.#refreshToken,
      }),
    });
    this.#log.info(`Response: ${response.status}`);
    if (!response.ok) {
      throw new Error('Failed to logout');
    }
    this.#accessToken = undefined;
    this.#refreshToken = undefined;
    this.#dpop = undefined;
  }

  /**
   * logoutWithRedirect logs out the user by revoking the refresh token and redirects to the specified URL.
   * @param {string} redirectUri The URL to redirect to after logout.
   */
  logoutWithRedirect(redirectUri) {
    window.location.href = this.#endSessionEndpoint + '?client_id=' + this.#clientId + '&post_logout_redirect_uri=' + redirectUri;
  }

  /**
   * handleRedirect handles the redirect from the login page.
   * @returns {Promise} A promise that resolves with the token response.
   * @throws {Error} If the token cannot be fetched.
   */
  async handleRedirect() {
    // Fetch the well-known endpoints.
    const config = await this.#fetchWellKnownEndpoint(this.#wellKnownEndpoint);
    this.#authEndpoint = config.authorization_endpoint;
    this.#tokenEndpoint = config.token_endpoint;
    this.#endSessionEndpoint = config.end_session_endpoint;

    // When redirected back from the login page, it will have an authorization code in the URL.
    // For example: http://example.com/callback#code=AUTHORIZATION_CODE
    const fragment = window.location.hash.substring(1);
    this.#log.info('Received fragment', fragment);
    const params = new URLSearchParams(fragment);
    const code = params.get('code');
    if (code) {
      try {
        const response = await this.#fetchTokenWithAuthorizationCode(code);
        this.#accessToken = response.access_token;
        this.#refreshToken = response.refresh_token;
        return response;
      } catch (error) {
        throw new Error(error.message);
      }
    }
    this.#log.info('No authorization code found in the URL');
    return null;
  }

  //
  // Private methods
  //

  // Fetch the well-known endpoint to get the authorization and token endpoints.
  async #fetchWellKnownEndpoint() {
    try {
      this.#log.info(`GET ${this.#wellKnownEndpoint}`);
      const response = await fetch(this.#wellKnownEndpoint);
      if (!response.ok) {
        throw new Error(`Failed to fetch well-known configuration: ${this.#wellKnownEndpoint}: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      throw new Error(`Failed to fetch well-known configuration: ${this.#wellKnownEndpoint}: ${error}`);
    }
  }

  // Fetch token using authorization code
  async #fetchTokenWithAuthorizationCode(code) {
    let body = {
      code: code,
      client_id: this.#clientId,
      redirect_uri: this.#redirectUri,
      grant_type: 'authorization_code',
    };

    if (this.#usePkce) {
      this.#log.info('PKCE is enabled. Sending code_verifier.');
      body.code_verifier = localStorage.getItem('code-verifier');
    }

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (this.#useDpop) {
      this.#dpop = new OAuthDPop();
      headers.DPoP = await this.#dpop.generateProof('POST', this.#tokenEndpoint);
      this.#log.info('DPoP is enabled. Sending DPoP proof JWT:', dpopStringify(headers.DPoP));
    }

    this.#log.info(
      `POST ${this.#tokenEndpoint} with body:`, JSON.stringify(body)
    );
    const response = await fetch(this.#tokenEndpoint, {
      method: 'POST',
      headers: headers,
      body: new URLSearchParams(body),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(
        `Failed to fetch token: status=${response.status} error=${error.error} error_description=${error.error_description} `
      );
    }

    const data = await response.json();
    this.#log.info('Received token response', JSON.stringify(data));
    return data;
  }

  // Fetch token using refresh token
  async #fetchTokenWithRefreshToken() {
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (this.#useDpop) {
      if (!this.#dpop) {
        throw new Error('Cannot refresh token without DPoP key pair generated during authorization_code grant request');
      }
      headers.DPoP = await this.#dpop.generateProof('POST', this.#tokenEndpoint);
      this.#log.info('DPoP is enabled. Sending DPoP proof JWT:', dpopStringify(headers.DPoP));
    }

    const body = {
      refresh_token: this.#refreshToken,
      client_id: this.#clientId,
      grant_type: 'refresh_token',
    };

    this.#log.info(
      `POST ${this.#tokenEndpoint} with body:`, JSON.stringify(body)
    );
    const response = await fetch(this.#tokenEndpoint, {
      method: 'POST',
      headers: headers,
      body: new URLSearchParams(body),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(
        `Failed to fetch token: status=${response.status} error=${error.error} error_description=${error.error_description} `
      );
    }
    const data = await response.json();
    this.#log.info('Received token response', JSON.stringify(data));
    return data;
  }
}

function tokenStringify(token) {
  const tokenJson = JSON.parse(atob(token.split('.')[1]));
  // Change the dates to human-readable format.
  tokenJson.iat = new Date(tokenJson.iat * 1000).toLocaleString(navigator.language);
  tokenJson.exp = new Date(tokenJson.exp * 1000).toLocaleString(navigator.language);
  return `${JSON.stringify(tokenJson, null, 2)}`;
}

export { OAuth, tokenStringify };
