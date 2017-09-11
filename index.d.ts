declare module 'adal-node' {

    export interface Logging {
        // TODO
    }

    export interface MemoryCache extends TokenCache {
        // TODO
    }

    export function setGlobalADALOptions(): any; // TODO
    export function getGlobalADALOptions(): any; // TODO

    /**
     * Contains tokens and metadata upon successful completion of an acquireToken call.
     * @typedef TokenResponse
     * @property {string} tokenType The type of token returned.
     * @property {string} accessToken The returned access token.
     * @property {string} [refreshToken] A refresh token.
     * @property {Date} [createdOn] The date on which the access token was created.
     * @property {Date} expiresOn The Date on which the access token expires.
     * @property {int} expiresIn The amount of time, in seconds, for which the token is valid.
     * @property {string} [userId] An id for the user.  May be a displayable value if is_user_id_displayable is true.
     * @property {bool}   [isUserIdDisplayable] Indicates whether the user_id property will be meaningful if displayed to a user.
     * @property {string} [tenantId] The identifier of the tenant under which the access token was issued.
     * @property {string} [givenName] The given name of the principal represented by the access token.
     * @property {string} [familyName] The family name of the principal represented by the access token.
     * @property {string} [identityProvider] Identifies the identity provider that issued the access token.
     */
    export interface TokenResponse {
        tokenType: string,
        expiresIn: number,
        expiresOn: Date,
        resource: string,
        accessToken: string
        // TODO
    }

    /**
     * This will be returned in case the OAuth 2 service returns an error.
     * @typedef ErrorResponse
     * @property {string} [error] A server error.
     * @property {string} [errorDescription] A description of the error returned.
     */
    export interface ErrorResponse {
        error: string;
        errorDescription: string;
    }

    /**
     * This is the callback that is passed to all acquireToken variants below.
     * @callback AcquireTokenCallback
     * @param {Error}  [error]           If the request fails this parameter will contain an Error object.
     * @param {TokenResponse|ErrorResponse} [response]   On a succesful request returns a {@link TokenResposne}.
     */
    export type AcquireTokenCallback = (error: Error, response: TokenResponse | ErrorResponse) => void;

    /**
     * This is an interface that can be implemented to provide custom token cache persistence.
     * @public
     * @class TokenCache
     * @property {ModifyCacheFunction}  add Called by ADAL when entries should be added to the cache.
     * @property {ModifyCacheFunction}  remove Called by ADAL when entries should be removed from the cache.
     * @property {FindCacheFunction}    find Called when ADAL needs to find entries in the cache.
     */
    export interface TokenCache {
        // TODO
    }

    export class AuthenticationContext {

        public authority: string;
        public correlationId: string;
        public options: any;
        public cache: TokenCache;

        /**
         * Creates a new AuthenticationContext object.  By default the authority will be checked against
         * a list of known Azure Active Directory authorities.  If the authority is not recognized as
         * one of these well known authorities then token acquisition will fail.  This behavior can be
         * turned off via the validateAuthority parameter below.
         * @constructor
         * @param {string}  authority            A URL that identifies a token authority.
         * @param {bool}   [validateAuthority]   Turns authority validation on or off.  This parameter default to true.
         * @param {TokenCache}   [cache]         Sets the token cache used by this AuthenticationContext instance.  If this parameter is not set
         *                                       then a default, in memory cache is used.  The default in memory cache is global to the process and is
         *                                       shared by all AuthenticationContexts that are created with an empty cache parameter.  To control the
         *                                       scope and lifetime of a cache you can either create a {@link MemoryCache} instance and pass it when
         *                                       constructing an AuthenticationContext or implement a custom {@link TokenCache} and pass that.  Cache
         *                                       instances passed at AuthenticationContext construction time are only used by that instance of
         *                                       the AuthenticationContext and are not shared unless it has been manually passed during the
         *                                       construction of other AuthenticationContexts.
         *
         */
        constructor(authority: string, validateAuthority?: boolean, cache?: TokenCache);

        /**
         * Gets a token for a given resource.
         * @param {string}   resource                            A URI that identifies the resource for which the token is valid.
         * @param {string}   clientId                            The OAuth client id of the calling application.
         * @param {string}   clientSecret                        The OAuth client secret of the calling application.
         * @param {AcquireTokenCallback}   callback              The callback function.
         */
        public acquireTokenWithClientCredentials(resource: string, clientId: string, clientSecret: string, callback: AcquireTokenCallback): void;

        /**
         * Gets a token for a given resource.
         * @param {string}   resource                            A URI that identifies the resource for which the token is valid.
         * @param {string}   username                            The username of the user on behalf this application is authenticating.
         * @param {string}   password                            The password of the user named in the username parameter.
         * @param {string}   clientId                            The OAuth client id of the calling application.
         * @param {AcquireTokenCallback}   callback              The callback function.
         */
        public acquireTokenWithUsernamePassword(resource: string, username: string, password: string, clientId: string, callback: AcquireTokenCallback): void;

        /**
         * Gets a token for a given resource.
         * @param {string}   authorizationCode                   An authorization code returned from a client.
         * @param {string}   redirectUri                         The redirect uri that was used in the authorize call.
         * @param {string}   resource                            A URI that identifies the resource for which the token is valid.
         * @param {string}   clientId                            The OAuth client id of the calling application.
         * @param {string}   clientSecret                        The OAuth client secret of the calling application.
         * @param {AcquireTokenCallback}   callback              The callback function.
         */
        public acquireTokenWithAuthorizationCode(authorizationCode: string, redirectUri: string, resource: string, clientId: string, clientSecret: string, callback: AcquireTokenCallback): void;

        /**
         * Gets a new access token via a previously issued refresh token.
         * @param  {string}   refreshToken                        A refresh token returned in a tokne response from a previous invocation of acquireToken.
         * @param  {string}   clientId                            The OAuth client id of the calling application.
         * @param  {string}   [clientSecret]                      The OAuth client secret of the calling application.  (Note: this parameter is a late addition.
         *                                                        This parameter may be ommitted entirely so that applications built before this change will continue
         *                                                        to work unchanged.)
         * @param  {string}   resource                            The OAuth resource for which a token is being request.  This parameter is optional and can be set to null.
         * @param  {AcquireTokenCallback}   callback              The callback function.
         */
        public acquireTokenWithRefreshToken(refreshToken: string, clientId: string, clientSecret: string, resource: string, callback: AcquireTokenCallback): void;

        /**
         * Gets a token for a given resource.
         * @param {string}   resource                            A URI that identifies the resource for which the token is valid.
         * @param {string}   [userId]                            The username of the user on behalf this application is authenticating.
         * @param {string}   [clientId]                          The OAuth client id of the calling application.
         * @param {AcquireTokenCallback}   callback              The callback function.
         */
        public acquireToken(resource: string, userId: string, clientId: string, callback: AcquireTokenCallback): void

        /**
         * Gets the userCodeInfo which contains user_code, device_code for authenticating user on device. 
         * @param  {string}   resource                            A URI that identifies the resource for which the device_code and user_code is valid for.
         * @param  {string}   clientId                            The OAuth client id of the calling application.
         * @param  {string}   language                            The language code specifying how the message should be localized to. 
         * @param  {AcquireTokenCallback}   callback              The callback function.
         */
        public acquireUserCode(resource: string, clientId: string, language: string, callback: AcquireTokenCallback): void; 

        /**
         * Gets a new access token using via a device code.
         * @note This method doesn't look up the cache, it only stores the returned token into cache. To look up cache before making a new request, 
         *       please use acquireToken.  
         * @param  {string}   clientId                            The OAuth client id of the calling application.
         * @param  {object}   userCodeInfo                        Contains device_code, retry interval, and expire time for the request for get the token. 
         * @param  {AcquireTokenCallback}   callback              The callback function.
         */
        public acquireTokenWithDeviceCode(resource: string, clientId: string, userCodeInfo: string, callback: AcquireTokenCallback): void;

        /**
         * Cancels the polling request to get token with device code. 
         * @param  {object}   userCodeInfo                        Contains device_code, retry interval, and expire time for the request for get the token. 
         * @param  {AcquireTokenCallback}   callback              The callback function.
         */
        public cancelRequestToGetTokenWithDeviceCode(userCodeInfo: any, callback: AcquireTokenCallback): void;
    }

    /**
     * Creates a new AuthenticationContext object.  By default the authority will be checked against
     * a list of known Azure Active Directory authorities.  If the authority is not recognized as
     * one of these well known authorities then token acquisition will fail.  This behavior can be
     * turned off via the validateAuthority parameter below.
     * @function
     * @param {string}  authority            A URL that identifies a token authority.
     * @param {bool}    [validateAuthority]  Turns authority validation on or off.  This parameter default to true.
     * @returns {AuthenticationContext}      A new authentication context.
     */
    export function createAuthenticationContext(authority: string, validateAuthority?: boolean): AuthenticationContext;
}

// declare module 'adal-node/*'{
//     var _a: any;
//     export = _a;
// }

