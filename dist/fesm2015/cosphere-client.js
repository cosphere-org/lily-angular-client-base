import { Injectable, Inject, NgModule, Injector, defineInjectable, inject } from '@angular/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { BehaviorSubject, throwError } from 'rxjs';
import { catchError, retry, map, filter } from 'rxjs/operators';
import { has, isEmpty } from 'underscore';

class ClientService {
    constructor(config, http) {
        this.config = config;
        this.http = http;
        /**
         * State for all GET payloads
         */
        this.state = new Map();
        this.defaultAuthToken = 'auth_token';
        /**
         * Cache time - every GET request is taken only if the last one
         * was invoked not earlier then `cacheTime` mins ago.
         * Only successful responses are cached (2xx)
         */
        this.cacheTime = 1000 * 60 * 60; // 60 mins
        this.baseUrl = this.config.baseUrl;
        this.authToken =
            this.config.authToken || this.defaultAuthToken;
    }
    get(endpoint, options) {
        const url = this.getUrl(endpoint);
        const httpOptions = this.getHttpOptions(options);
        return this.http
            .get(url, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    }
    post(endpoint, body, options) {
        const url = this.getUrl(endpoint);
        const httpOptions = this.getHttpOptions(options);
        return this.http
            .post(url, body, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    }
    put(endpoint, body, options) {
        const url = this.getUrl(endpoint);
        const httpOptions = this.getHttpOptions(options);
        return this.http
            .put(url, body, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    }
    delete(endpoint, options) {
        const url = this.getUrl(endpoint);
        const httpOptions = this.getHttpOptions(options);
        return this.http
            .delete(url, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    }
    getDataState(endpoint, options) {
        const key = options && options.params ? `${endpoint}_${JSON.stringify(options.params)}` : endpoint;
        this.initState(key, options);
        let cache = true;
        let params;
        if (has(options, 'cache')) {
            cache = options.cache;
        }
        if (has(options, 'params')) {
            params = options.params;
        }
        // Get the endpoint state
        const state = this.state.get(key);
        // Do not allow invoke the same GET request while one is pending
        if (state.requestState.pending /*&& !_.isEmpty(params)*/) {
            return state.dataState;
        }
        const currentTime = +new Date();
        if (currentTime - state.requestState.cachedAt > this.cacheTime ||
            // !_.isEmpty(params) ||
            !cache) {
            state.requestState.pending = true;
            this.get(endpoint, options)
                .pipe(map(data => (options.responseMap ? data[options.responseMap] : data)))
                .subscribe(data => {
                state.dataState.data$.next(data);
                state.dataState.isData$.next(!isEmpty(data));
                state.dataState.loading$.next(false);
                state.requestState.pending = false;
                state.requestState.cachedAt = currentTime;
            }, err => {
                state.dataState.isData$.next(false);
                state.dataState.data$.error(null);
                state.dataState.loading$.next(false);
                state.requestState.pending = false;
            });
        }
        else {
            state.dataState.loading$.next(false);
        }
        return state.dataState;
    }
    initState(key, options) {
        if (!this.state.has(key)) {
            this.state.set(key, {
                dataState: {
                    loading$: new BehaviorSubject(true),
                    isData$: new BehaviorSubject(false),
                    data$: new BehaviorSubject(null)
                },
                requestState: {
                    cachedAt: 0,
                    pending: false
                }
            });
        }
        else {
            this.state.get(key).dataState.loading$.next(true);
        }
    }
    getHttpOptions(options) {
        const authorizationRequired = has(options, 'authorizationRequired')
            ? options.authorizationRequired
            : true;
        const etag = (options && options.etag) || undefined;
        let httpOptions = {
            headers: this.getHeaders(authorizationRequired, etag)
        };
        if (has(options, 'headers')) {
            // tslint:disable
            for (let key in options.headers) {
                httpOptions.headers[key] = options.headers[key];
            }
            // tslint:enable
        }
        if (has(options, 'params')) {
            httpOptions.params = options.params;
        }
        if (has(options, 'reportProgress')) {
            httpOptions.reportProgress = options.reportProgress;
        }
        return httpOptions;
    }
    getHeaders(authorizationRequired, etag) {
        let headers = {
            'Content-Type': 'application/json'
        };
        if (authorizationRequired) {
            headers['Authorization'] = `Bearer ${this.getToken()}`;
        }
        if (etag) {
            headers['ETag'] = etag;
        }
        return headers;
    }
    getUrl(endpoint) {
        return `${this.baseUrl}${endpoint}`;
    }
    getToken() {
        return localStorage.getItem(this.authToken);
    }
    handleError(error) {
        if (error.error instanceof ErrorEvent) {
            // A client-side or network error occurred. Handle it accordingly.
            console.error('An error occurred:', error.error.message);
        }
        else {
            // The backend returned an unsuccessful response code.
            // The response body may contain clues as to what went wrong,
            console.error(`Backend returned code ${error.status}, ` + `body was: ${error.error}`);
        }
        // return an observable with a user-facing error message
        return throwError('Something bad happened; please try again later.');
    }
}
ClientService.decorators = [
    { type: Injectable, args: [{
                providedIn: 'root'
            },] }
];
/** @nocollapse */
ClientService.ctorParameters = () => [
    { type: undefined, decorators: [{ type: Inject, args: ['config',] }] },
    { type: HttpClient }
];
ClientService.ngInjectableDef = defineInjectable({ factory: function ClientService_Factory() { return new ClientService(inject("config"), inject(HttpClient)); }, token: ClientService, providedIn: "root" });

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class AccountSettingsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Read Account Settings
     */
    readAccountsetting() {
        return this.client.getDataState('/account/settings/', { authorizationRequired: true });
    }
    readAccountsetting2() {
        return this.client.get('/account/settings/', { authorizationRequired: true });
    }
    /**
     * Update Account Settings
     */
    updateAccountsetting(body) {
        return this.client
            .put('/account/settings/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
AccountSettingsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
AccountSettingsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class AccountsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Activate Account
     * -------------
     *
     * Activate Account by decoding the `code` which contains the confirmation off the intent and was signed by the user itself.
     */
    activateAccount(body) {
        return this.client
            .post('/auth/activate/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Bulk Read Mentors' Account
     * -------------
     *
     * Enable one to Read all available Mentor accounts
     */
    bulkReadAccounts(params) {
        return this.client.getDataState('/auth/accounts/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadAccounts2(params) {
        return this.client.get('/auth/accounts/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Change Password
     * -------------
     *
     * Enables one to change one's password for an authenticated user.
     */
    changePassword(body) {
        return this.client
            .post('/auth/change_password/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Account
     * -------------
     *
     * Creates User and Account if provided data are valid.
     */
    createAccount(body) {
        return this.client
            .post('/auth/accounts/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read My Account
     * -------------
     *
     * Read my Account data.
     */
    readAccount() {
        return this.client.getDataState('/auth/accounts/me/', { authorizationRequired: true });
    }
    readAccount2() {
        return this.client.get('/auth/accounts/me/', { authorizationRequired: true });
    }
    /**
     * Reset Password
     * -------------
     *
     * Enables one to reset her password in case the old one cannot be recalled.
     */
    resetPassword(body) {
        return this.client
            .post('/auth/reset_password/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Send Account Activation Email
     * -------------
     *
     * Send an Email containing the confirmation link which when clicked kicks of the Account Activation. Even though the activation email is send automatically during the Sign Up phase one should have a way to send it again in case it was not delivered.
     */
    sendAccountActivationEmail(body) {
        return this.client
            .post('/auth/send_activation_email/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Send Reset Password Email
     * -------------
     *
     * Send an Email containing the confirmation link which when clicked kicks of the real Reset Password operation.
     */
    sendResetPasswordEmail(body) {
        return this.client
            .post('/auth/send_reset_password_email/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Update My Account
     * -------------
     *
     * Update my Account data.
     */
    updateAccount(body) {
        return this.client
            .put('/auth/accounts/me/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
AccountsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
AccountsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-23
 */
var BulkReadAccountsResponseAtype;
(function (BulkReadAccountsResponseAtype) {
    BulkReadAccountsResponseAtype["ADMIN"] = "ADMIN";
    BulkReadAccountsResponseAtype["FREE"] = "FREE";
    BulkReadAccountsResponseAtype["LEARNER"] = "LEARNER";
    BulkReadAccountsResponseAtype["MENTOR"] = "MENTOR";
    BulkReadAccountsResponseAtype["PARTNER"] = "PARTNER";
})(BulkReadAccountsResponseAtype || (BulkReadAccountsResponseAtype = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-8
 */
var ReadAccountResponseAtype;
(function (ReadAccountResponseAtype) {
    ReadAccountResponseAtype["ADMIN"] = "ADMIN";
    ReadAccountResponseAtype["FREE"] = "FREE";
    ReadAccountResponseAtype["LEARNER"] = "LEARNER";
    ReadAccountResponseAtype["MENTOR"] = "MENTOR";
    ReadAccountResponseAtype["PARTNER"] = "PARTNER";
})(ReadAccountResponseAtype || (ReadAccountResponseAtype = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/account/serializers.py/#lines-8
 */
var UpdateAccountResponseAtype;
(function (UpdateAccountResponseAtype) {
    UpdateAccountResponseAtype["ADMIN"] = "ADMIN";
    UpdateAccountResponseAtype["FREE"] = "FREE";
    UpdateAccountResponseAtype["LEARNER"] = "LEARNER";
    UpdateAccountResponseAtype["MENTOR"] = "MENTOR";
    UpdateAccountResponseAtype["PARTNER"] = "PARTNER";
})(UpdateAccountResponseAtype || (UpdateAccountResponseAtype = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class AttemptStatsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Attempt Stats
     * -------------
     *
     * List Attempt Stats by filtering existing ones.
     */
    bulkReadAttemptstats(params) {
        return this.client.getDataState('/recall/attempt_stats/', { params, authorizationRequired: true });
    }
    bulkReadAttemptstats2(params) {
        return this.client.get('/recall/attempt_stats/', { params, authorizationRequired: true });
    }
    /**
     * Create Attempt Stat
     * -------------
     *
     * Create Attempt Stat which stores information about basis statistics of a particular recall attempt.
     */
    createAttemptstat(body) {
        return this.client
            .post('/recall/attempt_stats/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create External Attempt Stat
     * -------------
     *
     * Create External Attempt Stat meaning one which was rendered elsewhere in any of the multiple CoSphere apps.
     */
    createExternalAttemptStat(body) {
        return this.client
            .post('/recall/attempt_stats/external/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
AttemptStatsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
AttemptStatsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class AttemptsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Attempts By Card
     * -------------
     *
     * List Attempts for a specific Card given by its Id.
     */
    bulkReadAttemptsByCards(cardId) {
        return this.client.getDataState(`/recall/attempts/by_card/${cardId}`, { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadAttemptsByCards2(cardId) {
        return this.client.get(`/recall/attempts/by_card/${cardId}`, { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Create Attempt
     * -------------
     *
     * Create Attempt which is a reflection of someone's knowledge regarding a given Card.
     */
    createAttempt(body) {
        return this.client
            .post('/recall/attempts/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Update Attempt
     * -------------
     *
     * Update existing Attempt with new cells and / or style.
     */
    updateAttempt(attemptId, body) {
        return this.client
            .put(`/recall/attempts/${attemptId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
AttemptsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
AttemptsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class AuthTokensDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Authorize a given token
     * -------------
     *
     * Can be called by the API Gateway in order to authorize every request using provided token.
     */
    authorizeAuthToken() {
        return this.client
            .post('/auth/auth_tokens/authorize/', {}, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Sign In
     * -------------
     *
     * Validates data provided on the input and if successful returns auth token.
     */
    createAuthToken(body) {
        return this.client
            .post('/auth/auth_tokens/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Facebook Auth Token
     */
    createFacebookBasedAuthToken(body) {
        return this.client
            .post('/auth/auth_tokens/facebook/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Mobile Facebook Auth Token
     */
    createFacebookBasedMobileAuthToken(body) {
        return this.client
            .post('/auth/auth_tokens/facebook/mobile/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Google Auth Token
     */
    createGoogleBasedAuthToken(body) {
        return this.client
            .post('/auth/auth_tokens/google/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Mobile Google Auth Token
     */
    createGoogleBasedMobileAuthToken(body) {
        return this.client
            .post('/auth/auth_tokens/google/mobile/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Refresh JWT token
     * -------------
     *
     * Should be used whenever token is close to expiry or if one is requested to refresh the token because for example account type was changed and new token should be requested to reflect that change.
     */
    updateAuthToken() {
        return this.client
            .put('/auth/auth_tokens/', {}, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
AuthTokensDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
AuthTokensDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class BricksDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Bulk Read Bricks Game Attempts
     */
    bulkReadGameattempts(gameId) {
        return this.client.getDataState(`/games/${gameId}/attempts/`, { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadGameattempts2(gameId) {
        return this.client.get(`/games/${gameId}/attempts/`, { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Bulk Read Game
     */
    bulkReadGames() {
        return this.client.getDataState('/games/', { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadGames2() {
        return this.client.get('/games/', { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Create Game
     */
    createGame(body) {
        return this.client
            .post('/games/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Bricks Game Attempt
     */
    createGameattempt(gameId, body) {
        return this.client
            .post(`/games/${gameId}/attempts/`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Delete Game
     */
    deleteGame(gameId) {
        return this.client
            .delete(`/games/${gameId}`, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Game
     */
    readGame(gameId) {
        return this.client.getDataState(`/games/${gameId}`, { authorizationRequired: true });
    }
    readGame2(gameId) {
        return this.client.get(`/games/${gameId}`, { authorizationRequired: true });
    }
    /**
     * Update Game
     */
    updateGame(gameId, body) {
        return this.client
            .put(`/games/${gameId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
BricksDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
BricksDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * https://bitbucket.org/goodai/cosphere-app-bricks-be/src/9dfe86168ecc1beac0ce22a6ba200163f317fdba/cosphere_app_bricks_be/game/parsers.py/#lines-54
 */
var CreateGameBodyAudioLanguage;
(function (CreateGameBodyAudioLanguage) {
    CreateGameBodyAudioLanguage["cy"] = "cy";
    CreateGameBodyAudioLanguage["da"] = "da";
    CreateGameBodyAudioLanguage["de"] = "de";
    CreateGameBodyAudioLanguage["en"] = "en";
    CreateGameBodyAudioLanguage["es"] = "es";
    CreateGameBodyAudioLanguage["fr"] = "fr";
    CreateGameBodyAudioLanguage["is"] = "is";
    CreateGameBodyAudioLanguage["it"] = "it";
    CreateGameBodyAudioLanguage["ja"] = "ja";
    CreateGameBodyAudioLanguage["ko"] = "ko";
    CreateGameBodyAudioLanguage["nb"] = "nb";
    CreateGameBodyAudioLanguage["nl"] = "nl";
    CreateGameBodyAudioLanguage["pl"] = "pl";
    CreateGameBodyAudioLanguage["pt"] = "pt";
    CreateGameBodyAudioLanguage["ro"] = "ro";
    CreateGameBodyAudioLanguage["ru"] = "ru";
    CreateGameBodyAudioLanguage["sv"] = "sv";
    CreateGameBodyAudioLanguage["tr"] = "tr";
})(CreateGameBodyAudioLanguage || (CreateGameBodyAudioLanguage = {}));
var CreateGameBodyLanguage;
(function (CreateGameBodyLanguage) {
    CreateGameBodyLanguage["af"] = "af";
    CreateGameBodyLanguage["am"] = "am";
    CreateGameBodyLanguage["an"] = "an";
    CreateGameBodyLanguage["ar"] = "ar";
    CreateGameBodyLanguage["as"] = "as";
    CreateGameBodyLanguage["az"] = "az";
    CreateGameBodyLanguage["be"] = "be";
    CreateGameBodyLanguage["bg"] = "bg";
    CreateGameBodyLanguage["bn"] = "bn";
    CreateGameBodyLanguage["br"] = "br";
    CreateGameBodyLanguage["bs"] = "bs";
    CreateGameBodyLanguage["ca"] = "ca";
    CreateGameBodyLanguage["cs"] = "cs";
    CreateGameBodyLanguage["cy"] = "cy";
    CreateGameBodyLanguage["da"] = "da";
    CreateGameBodyLanguage["de"] = "de";
    CreateGameBodyLanguage["dz"] = "dz";
    CreateGameBodyLanguage["el"] = "el";
    CreateGameBodyLanguage["en"] = "en";
    CreateGameBodyLanguage["eo"] = "eo";
    CreateGameBodyLanguage["es"] = "es";
    CreateGameBodyLanguage["et"] = "et";
    CreateGameBodyLanguage["eu"] = "eu";
    CreateGameBodyLanguage["fa"] = "fa";
    CreateGameBodyLanguage["fi"] = "fi";
    CreateGameBodyLanguage["fo"] = "fo";
    CreateGameBodyLanguage["fr"] = "fr";
    CreateGameBodyLanguage["ga"] = "ga";
    CreateGameBodyLanguage["gl"] = "gl";
    CreateGameBodyLanguage["gu"] = "gu";
    CreateGameBodyLanguage["he"] = "he";
    CreateGameBodyLanguage["hi"] = "hi";
    CreateGameBodyLanguage["hr"] = "hr";
    CreateGameBodyLanguage["ht"] = "ht";
    CreateGameBodyLanguage["hu"] = "hu";
    CreateGameBodyLanguage["hy"] = "hy";
    CreateGameBodyLanguage["id"] = "id";
    CreateGameBodyLanguage["is"] = "is";
    CreateGameBodyLanguage["it"] = "it";
    CreateGameBodyLanguage["ja"] = "ja";
    CreateGameBodyLanguage["jv"] = "jv";
    CreateGameBodyLanguage["ka"] = "ka";
    CreateGameBodyLanguage["kk"] = "kk";
    CreateGameBodyLanguage["km"] = "km";
    CreateGameBodyLanguage["kn"] = "kn";
    CreateGameBodyLanguage["ko"] = "ko";
    CreateGameBodyLanguage["ku"] = "ku";
    CreateGameBodyLanguage["ky"] = "ky";
    CreateGameBodyLanguage["la"] = "la";
    CreateGameBodyLanguage["lb"] = "lb";
    CreateGameBodyLanguage["lo"] = "lo";
    CreateGameBodyLanguage["lt"] = "lt";
    CreateGameBodyLanguage["lv"] = "lv";
    CreateGameBodyLanguage["mg"] = "mg";
    CreateGameBodyLanguage["mk"] = "mk";
    CreateGameBodyLanguage["ml"] = "ml";
    CreateGameBodyLanguage["mn"] = "mn";
    CreateGameBodyLanguage["mr"] = "mr";
    CreateGameBodyLanguage["ms"] = "ms";
    CreateGameBodyLanguage["mt"] = "mt";
    CreateGameBodyLanguage["nb"] = "nb";
    CreateGameBodyLanguage["ne"] = "ne";
    CreateGameBodyLanguage["nl"] = "nl";
    CreateGameBodyLanguage["nn"] = "nn";
    CreateGameBodyLanguage["no"] = "no";
    CreateGameBodyLanguage["oc"] = "oc";
    CreateGameBodyLanguage["or"] = "or";
    CreateGameBodyLanguage["pa"] = "pa";
    CreateGameBodyLanguage["pl"] = "pl";
    CreateGameBodyLanguage["ps"] = "ps";
    CreateGameBodyLanguage["pt"] = "pt";
    CreateGameBodyLanguage["qu"] = "qu";
    CreateGameBodyLanguage["ro"] = "ro";
    CreateGameBodyLanguage["ru"] = "ru";
    CreateGameBodyLanguage["rw"] = "rw";
    CreateGameBodyLanguage["se"] = "se";
    CreateGameBodyLanguage["si"] = "si";
    CreateGameBodyLanguage["sk"] = "sk";
    CreateGameBodyLanguage["sl"] = "sl";
    CreateGameBodyLanguage["sq"] = "sq";
    CreateGameBodyLanguage["sr"] = "sr";
    CreateGameBodyLanguage["sv"] = "sv";
    CreateGameBodyLanguage["sw"] = "sw";
    CreateGameBodyLanguage["ta"] = "ta";
    CreateGameBodyLanguage["te"] = "te";
    CreateGameBodyLanguage["th"] = "th";
    CreateGameBodyLanguage["tl"] = "tl";
    CreateGameBodyLanguage["tr"] = "tr";
    CreateGameBodyLanguage["ug"] = "ug";
    CreateGameBodyLanguage["uk"] = "uk";
    CreateGameBodyLanguage["ur"] = "ur";
    CreateGameBodyLanguage["vi"] = "vi";
    CreateGameBodyLanguage["vo"] = "vo";
    CreateGameBodyLanguage["wa"] = "wa";
    CreateGameBodyLanguage["xh"] = "xh";
    CreateGameBodyLanguage["zh"] = "zh";
    CreateGameBodyLanguage["zu"] = "zu";
})(CreateGameBodyLanguage || (CreateGameBodyLanguage = {}));
/**
 * https://bitbucket.org/goodai/cosphere-app-bricks-be/src/9dfe86168ecc1beac0ce22a6ba200163f317fdba/cosphere_app_bricks_be/game/parsers.py/#lines-54
 */
var UpdateGameBodyAudioLanguage;
(function (UpdateGameBodyAudioLanguage) {
    UpdateGameBodyAudioLanguage["cy"] = "cy";
    UpdateGameBodyAudioLanguage["da"] = "da";
    UpdateGameBodyAudioLanguage["de"] = "de";
    UpdateGameBodyAudioLanguage["en"] = "en";
    UpdateGameBodyAudioLanguage["es"] = "es";
    UpdateGameBodyAudioLanguage["fr"] = "fr";
    UpdateGameBodyAudioLanguage["is"] = "is";
    UpdateGameBodyAudioLanguage["it"] = "it";
    UpdateGameBodyAudioLanguage["ja"] = "ja";
    UpdateGameBodyAudioLanguage["ko"] = "ko";
    UpdateGameBodyAudioLanguage["nb"] = "nb";
    UpdateGameBodyAudioLanguage["nl"] = "nl";
    UpdateGameBodyAudioLanguage["pl"] = "pl";
    UpdateGameBodyAudioLanguage["pt"] = "pt";
    UpdateGameBodyAudioLanguage["ro"] = "ro";
    UpdateGameBodyAudioLanguage["ru"] = "ru";
    UpdateGameBodyAudioLanguage["sv"] = "sv";
    UpdateGameBodyAudioLanguage["tr"] = "tr";
})(UpdateGameBodyAudioLanguage || (UpdateGameBodyAudioLanguage = {}));
var UpdateGameBodyLanguage;
(function (UpdateGameBodyLanguage) {
    UpdateGameBodyLanguage["af"] = "af";
    UpdateGameBodyLanguage["am"] = "am";
    UpdateGameBodyLanguage["an"] = "an";
    UpdateGameBodyLanguage["ar"] = "ar";
    UpdateGameBodyLanguage["as"] = "as";
    UpdateGameBodyLanguage["az"] = "az";
    UpdateGameBodyLanguage["be"] = "be";
    UpdateGameBodyLanguage["bg"] = "bg";
    UpdateGameBodyLanguage["bn"] = "bn";
    UpdateGameBodyLanguage["br"] = "br";
    UpdateGameBodyLanguage["bs"] = "bs";
    UpdateGameBodyLanguage["ca"] = "ca";
    UpdateGameBodyLanguage["cs"] = "cs";
    UpdateGameBodyLanguage["cy"] = "cy";
    UpdateGameBodyLanguage["da"] = "da";
    UpdateGameBodyLanguage["de"] = "de";
    UpdateGameBodyLanguage["dz"] = "dz";
    UpdateGameBodyLanguage["el"] = "el";
    UpdateGameBodyLanguage["en"] = "en";
    UpdateGameBodyLanguage["eo"] = "eo";
    UpdateGameBodyLanguage["es"] = "es";
    UpdateGameBodyLanguage["et"] = "et";
    UpdateGameBodyLanguage["eu"] = "eu";
    UpdateGameBodyLanguage["fa"] = "fa";
    UpdateGameBodyLanguage["fi"] = "fi";
    UpdateGameBodyLanguage["fo"] = "fo";
    UpdateGameBodyLanguage["fr"] = "fr";
    UpdateGameBodyLanguage["ga"] = "ga";
    UpdateGameBodyLanguage["gl"] = "gl";
    UpdateGameBodyLanguage["gu"] = "gu";
    UpdateGameBodyLanguage["he"] = "he";
    UpdateGameBodyLanguage["hi"] = "hi";
    UpdateGameBodyLanguage["hr"] = "hr";
    UpdateGameBodyLanguage["ht"] = "ht";
    UpdateGameBodyLanguage["hu"] = "hu";
    UpdateGameBodyLanguage["hy"] = "hy";
    UpdateGameBodyLanguage["id"] = "id";
    UpdateGameBodyLanguage["is"] = "is";
    UpdateGameBodyLanguage["it"] = "it";
    UpdateGameBodyLanguage["ja"] = "ja";
    UpdateGameBodyLanguage["jv"] = "jv";
    UpdateGameBodyLanguage["ka"] = "ka";
    UpdateGameBodyLanguage["kk"] = "kk";
    UpdateGameBodyLanguage["km"] = "km";
    UpdateGameBodyLanguage["kn"] = "kn";
    UpdateGameBodyLanguage["ko"] = "ko";
    UpdateGameBodyLanguage["ku"] = "ku";
    UpdateGameBodyLanguage["ky"] = "ky";
    UpdateGameBodyLanguage["la"] = "la";
    UpdateGameBodyLanguage["lb"] = "lb";
    UpdateGameBodyLanguage["lo"] = "lo";
    UpdateGameBodyLanguage["lt"] = "lt";
    UpdateGameBodyLanguage["lv"] = "lv";
    UpdateGameBodyLanguage["mg"] = "mg";
    UpdateGameBodyLanguage["mk"] = "mk";
    UpdateGameBodyLanguage["ml"] = "ml";
    UpdateGameBodyLanguage["mn"] = "mn";
    UpdateGameBodyLanguage["mr"] = "mr";
    UpdateGameBodyLanguage["ms"] = "ms";
    UpdateGameBodyLanguage["mt"] = "mt";
    UpdateGameBodyLanguage["nb"] = "nb";
    UpdateGameBodyLanguage["ne"] = "ne";
    UpdateGameBodyLanguage["nl"] = "nl";
    UpdateGameBodyLanguage["nn"] = "nn";
    UpdateGameBodyLanguage["no"] = "no";
    UpdateGameBodyLanguage["oc"] = "oc";
    UpdateGameBodyLanguage["or"] = "or";
    UpdateGameBodyLanguage["pa"] = "pa";
    UpdateGameBodyLanguage["pl"] = "pl";
    UpdateGameBodyLanguage["ps"] = "ps";
    UpdateGameBodyLanguage["pt"] = "pt";
    UpdateGameBodyLanguage["qu"] = "qu";
    UpdateGameBodyLanguage["ro"] = "ro";
    UpdateGameBodyLanguage["ru"] = "ru";
    UpdateGameBodyLanguage["rw"] = "rw";
    UpdateGameBodyLanguage["se"] = "se";
    UpdateGameBodyLanguage["si"] = "si";
    UpdateGameBodyLanguage["sk"] = "sk";
    UpdateGameBodyLanguage["sl"] = "sl";
    UpdateGameBodyLanguage["sq"] = "sq";
    UpdateGameBodyLanguage["sr"] = "sr";
    UpdateGameBodyLanguage["sv"] = "sv";
    UpdateGameBodyLanguage["sw"] = "sw";
    UpdateGameBodyLanguage["ta"] = "ta";
    UpdateGameBodyLanguage["te"] = "te";
    UpdateGameBodyLanguage["th"] = "th";
    UpdateGameBodyLanguage["tl"] = "tl";
    UpdateGameBodyLanguage["tr"] = "tr";
    UpdateGameBodyLanguage["ug"] = "ug";
    UpdateGameBodyLanguage["uk"] = "uk";
    UpdateGameBodyLanguage["ur"] = "ur";
    UpdateGameBodyLanguage["vi"] = "vi";
    UpdateGameBodyLanguage["vo"] = "vo";
    UpdateGameBodyLanguage["wa"] = "wa";
    UpdateGameBodyLanguage["xh"] = "xh";
    UpdateGameBodyLanguage["zh"] = "zh";
    UpdateGameBodyLanguage["zu"] = "zu";
})(UpdateGameBodyLanguage || (UpdateGameBodyLanguage = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class CardsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Remove Card
     * -------------
     *
     * Remove list of Cards specified by their ids.
     */
    bulkDeleteCards(params) {
        return this.client
            .delete('/cards/', { params, authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Bulk Read Multiple Cards
     * -------------
     *
     * List subset of Cards depending on various filtering flags.
     */
    bulkReadCards(params) {
        return this.client.getDataState('/cards/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadCards2(params) {
        return this.client.get('/cards/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    createCard(body) {
        return this.client
            .post('/cards/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Card by Id
     * -------------
     *
     * Read Card by `id`.
     */
    readCard(cardId) {
        return this.client.getDataState(`/cards/${cardId}`, { authorizationRequired: true });
    }
    readCard2(cardId) {
        return this.client.get(`/cards/${cardId}`, { authorizationRequired: true });
    }
    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    updateCard(cardId, body) {
        return this.client
            .put(`/cards/${cardId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
CardsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
CardsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class CategoriesDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Categories
     * -------------
     *
     * List Categories.
     */
    bulkReadCategories() {
        return this.client.getDataState('/categories/', { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadCategories2() {
        return this.client.get('/categories/', { responseMap: 'data', authorizationRequired: true });
    }
}
CategoriesDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
CategoriesDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Categories Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/category/serializers.py/#lines-27
 */
var BulkReadCategoriesResponseText;
(function (BulkReadCategoriesResponseText) {
    BulkReadCategoriesResponseText["FORGOTTEN"] = "FORGOTTEN";
    BulkReadCategoriesResponseText["HOT"] = "HOT";
    BulkReadCategoriesResponseText["NOT_RECALLED"] = "NOT_RECALLED";
    BulkReadCategoriesResponseText["PROBLEMATIC"] = "PROBLEMATIC";
    BulkReadCategoriesResponseText["RECENTLY_ADDED"] = "RECENTLY_ADDED";
})(BulkReadCategoriesResponseText || (BulkReadCategoriesResponseText = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class ContactsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Create Anonymous Contact Attempt
     * -------------
     *
     * Enables one to send messages to CoSphere's support even if the sender is not authenticated.
     */
    createAnonymousContactAttempt(body) {
        return this.client
            .post('/contacts/anonymous/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Send Authenticated Contact Message
     * -------------
     *
     * Send the Contact Message immediately since it's already for an existing and authenticated user.
     */
    sendAuthenticatedContactMessage(body) {
        return this.client
            .post('/contacts/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Verify the contact attempt
     * -------------
     *
     * Verify the correctness of provided verification code and send the message to the CoSphere's support. This mechanism is used for anonymous users only.
     */
    verifyAnonymousContactAttempt(body) {
        return this.client
            .post('/contacts/anonymous/verify/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
}
ContactsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
ContactsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class DonationsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Check if one can attempt a request displaying donation
     * -------------
     *
     * Since we don't want to overflow user with unnecessary requests for him donating we do it in a smarter way using set of heuristics that together help us to answer the following question: "Is it the best moment to ask for the donation?". Currently we use the following heuristics: - is account old enough? - whether user recently donated - whether we attempted recently to request donation from the user - if the user in a good mood (after doing some successful recalls)
     */
    checkIfCanAttemptDonation(params) {
        return this.client.getDataState('/payments/donations/can_attempt/', { params, authorizationRequired: true });
    }
    checkIfCanAttemptDonation2(params) {
        return this.client.get('/payments/donations/can_attempt/', { params, authorizationRequired: true });
    }
    /**
     * Register anonymous donation
     * -------------
     *
     * One can perform a donation payment even if not being an authenticated user. Even in that case we cannot allow full anonymity and we must require at least email address to send information regarding the status of the payment.
     */
    createAnonymousDonation(body) {
        return this.client
            .post('/payments/donations/register_anonymous/', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Register donation from authenticated user
     * -------------
     *
     * One can perform a donation payment even as an authenticated user.
     */
    createDonation(body) {
        return this.client
            .post('/payments/donations/register/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create donation attempt for authenticated user
     * -------------
     *
     * Each Donation Attempt should be followed by creation of Donation Attempt model instance to reflect that fact. It allows one to track how many times we asked a certain user about the donation in order not to overflow that user with them and not to be too aggressive.
     */
    createDonationattempt(body) {
        return this.client
            .post('/payments/donations/attempts/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
DonationsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
DonationsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Donations Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/views/donation.py/#lines-30
 */
var CheckIfCanAttemptDonationQueryEvent;
(function (CheckIfCanAttemptDonationQueryEvent) {
    CheckIfCanAttemptDonationQueryEvent["CLOSE"] = "CLOSE";
    CheckIfCanAttemptDonationQueryEvent["RECALL"] = "RECALL";
    CheckIfCanAttemptDonationQueryEvent["START"] = "START";
})(CheckIfCanAttemptDonationQueryEvent || (CheckIfCanAttemptDonationQueryEvent = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment.py/#lines-9
 */
var CreateAnonymousDonationResponseCurrency;
(function (CreateAnonymousDonationResponseCurrency) {
    CreateAnonymousDonationResponseCurrency["PLN"] = "PLN";
})(CreateAnonymousDonationResponseCurrency || (CreateAnonymousDonationResponseCurrency = {}));
var CreateAnonymousDonationResponseProductType;
(function (CreateAnonymousDonationResponseProductType) {
    CreateAnonymousDonationResponseProductType["DONATION"] = "DONATION";
    CreateAnonymousDonationResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    CreateAnonymousDonationResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    CreateAnonymousDonationResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    CreateAnonymousDonationResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(CreateAnonymousDonationResponseProductType || (CreateAnonymousDonationResponseProductType = {}));
var CreateAnonymousDonationResponseStatus;
(function (CreateAnonymousDonationResponseStatus) {
    CreateAnonymousDonationResponseStatus["CANCELED"] = "CANCELED";
    CreateAnonymousDonationResponseStatus["COMPLETED"] = "COMPLETED";
    CreateAnonymousDonationResponseStatus["NEW"] = "NEW";
    CreateAnonymousDonationResponseStatus["PENDING"] = "PENDING";
    CreateAnonymousDonationResponseStatus["REJECTED"] = "REJECTED";
})(CreateAnonymousDonationResponseStatus || (CreateAnonymousDonationResponseStatus = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment.py/#lines-9
 */
var CreateDonationResponseCurrency;
(function (CreateDonationResponseCurrency) {
    CreateDonationResponseCurrency["PLN"] = "PLN";
})(CreateDonationResponseCurrency || (CreateDonationResponseCurrency = {}));
var CreateDonationResponseProductType;
(function (CreateDonationResponseProductType) {
    CreateDonationResponseProductType["DONATION"] = "DONATION";
    CreateDonationResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    CreateDonationResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    CreateDonationResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    CreateDonationResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(CreateDonationResponseProductType || (CreateDonationResponseProductType = {}));
var CreateDonationResponseStatus;
(function (CreateDonationResponseStatus) {
    CreateDonationResponseStatus["CANCELED"] = "CANCELED";
    CreateDonationResponseStatus["COMPLETED"] = "COMPLETED";
    CreateDonationResponseStatus["NEW"] = "NEW";
    CreateDonationResponseStatus["PENDING"] = "PENDING";
    CreateDonationResponseStatus["REJECTED"] = "REJECTED";
})(CreateDonationResponseStatus || (CreateDonationResponseStatus = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/views/donation.py/#lines-184
 */
var CreateDonationattemptBodyEvent;
(function (CreateDonationattemptBodyEvent) {
    CreateDonationattemptBodyEvent["CLOSE"] = "CLOSE";
    CreateDonationattemptBodyEvent["RECALL"] = "RECALL";
    CreateDonationattemptBodyEvent["START"] = "START";
})(CreateDonationattemptBodyEvent || (CreateDonationattemptBodyEvent = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/donation.py/#lines-8
 */
var CreateDonationattemptResponseEvent;
(function (CreateDonationattemptResponseEvent) {
    CreateDonationattemptResponseEvent["CLOSE"] = "CLOSE";
    CreateDonationattemptResponseEvent["RECALL"] = "RECALL";
    CreateDonationattemptResponseEvent["START"] = "START";
})(CreateDonationattemptResponseEvent || (CreateDonationattemptResponseEvent = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class ExternalAppsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Authorize a given external app token
     * -------------
     *
     * Can be called by the API Gateway in order to authorize every request using provided token. It must be used only for external app tokens, which are used by the external apps to make calls on behalf of a given user.
     */
    authorizeExternalAppAuthToken() {
        return this.client
            .post('/external/auth_tokens/authorize/', {}, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read External App Configuration
     */
    createExternalAppAuthToken(body) {
        return this.client
            .post('/external/auth_tokens/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read External App configuration
     */
    readExternalappconf(params) {
        return this.client.getDataState('/external/apps/', { params, authorizationRequired: true });
    }
    readExternalappconf2(params) {
        return this.client.get('/external/apps/', { params, authorizationRequired: true });
    }
}
ExternalAppsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
ExternalAppsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class FocusRecordsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Create Focus Record
     */
    createFocusrecord(body) {
        return this.client
            .post('/focus_records/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Focus Record Summary
     */
    readFocusRecordSummary() {
        return this.client.getDataState('/focus_records/summary/', { authorizationRequired: true });
    }
    readFocusRecordSummary2() {
        return this.client.get('/focus_records/summary/', { authorizationRequired: true });
    }
}
FocusRecordsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
FocusRecordsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class FragmentHashtagsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Hashtags
     * -------------
     *
     * List Hashtags
     */
    bulkReadFragmentHashtags(params) {
        return this.client.getDataState('/fragments/hashtags/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadFragmentHashtags2(params) {
        return this.client.get('/fragments/hashtags/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * List Published Hashtags
     * -------------
     *
     * List Published Hashtags
     */
    bulkReadPublishedFragmentHashtags(params) {
        return this.client.getDataState('/fragments/hashtags/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
    bulkReadPublishedFragmentHashtags2(params) {
        return this.client.get('/fragments/hashtags/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
}
FragmentHashtagsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
FragmentHashtagsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class FragmentWordsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Words
     * -------------
     *
     * List Words
     */
    bulkReadFragmentWords(params) {
        return this.client.getDataState('/fragments/words/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadFragmentWords2(params) {
        return this.client.get('/fragments/words/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * List Published Words
     * -------------
     *
     * List Published Words
     */
    bulkReadPublishedFragmentWords(params) {
        return this.client.getDataState('/fragments/words/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
    bulkReadPublishedFragmentWords2(params) {
        return this.client.get('/fragments/words/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
}
FragmentWordsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
FragmentWordsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class FragmentsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Remote Fragments
     * -------------
     *
     * List Remote Fragments
     */
    bulkReadFragments(params) {
        return this.client.getDataState('/fragments/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadFragments2(params) {
        return this.client.get('/fragments/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * List Published Remote Fragments
     * -------------
     *
     * List Published Remote Fragments
     */
    bulkReadPublishedFragments(params) {
        return this.client.getDataState('/fragments/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
    bulkReadPublishedFragments2(params) {
        return this.client.get('/fragments/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
    /**
     * Create Remote Fragment
     * -------------
     *
     * Create Remote Fragment
     */
    createFragment() {
        return this.client
            .post('/fragments/', {}, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Delete Remote Fragment
     * -------------
     *
     * Delete Remote Fragment
     */
    deleteFragment(fragmentId) {
        return this.client
            .delete(`/fragments/${fragmentId}`, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Merge Remote Fragment
     * -------------
     *
     * Merge Remote Fragment
     */
    mergeFragment(fragmentId) {
        return this.client
            .post(`/fragments/${fragmentId}/merge/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Publish Remote Fragment
     * -------------
     *
     * Publish Remote Fragment
     */
    publishFragment(fragmentId) {
        return this.client
            .put(`/fragments/${fragmentId}/publish/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Remote Fragment
     * -------------
     *
     * Read Remote Fragment
     */
    readFragment(fragmentId) {
        return this.client.getDataState(`/fragments/${fragmentId}`, { authorizationRequired: true });
    }
    readFragment2(fragmentId) {
        return this.client.get(`/fragments/${fragmentId}`, { authorizationRequired: true });
    }
    /**
     * Read Fragment Diff
     * -------------
     *
     * Read Fragment Diff
     */
    readFragmentDiff(fragmentId) {
        return this.client.getDataState(`/fragments/${fragmentId}/diff/`, { authorizationRequired: true });
    }
    readFragmentDiff2(fragmentId) {
        return this.client.get(`/fragments/${fragmentId}/diff/`, { authorizationRequired: true });
    }
    /**
     * Read Fragment Sample
     * -------------
     *
     * Read Fragment Sample
     */
    readFragmentSample(fragmentId) {
        return this.client.getDataState(`/fragments/${fragmentId}/sample/`, { authorizationRequired: false });
    }
    readFragmentSample2(fragmentId) {
        return this.client.get(`/fragments/${fragmentId}/sample/`, { authorizationRequired: false });
    }
    /**
     * Update Remote Fragment
     * -------------
     *
     * Update Remote Fragment
     */
    updateFragment(fragmentId, body) {
        return this.client
            .put(`/fragments/${fragmentId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
FragmentsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
FragmentsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class GeometriesDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Geometries
     * -------------
     *
     * List Geometries.
     */
    bulkReadGeometries(params) {
        return this.client.getDataState('/grid/geometries/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadGeometries2(params) {
        return this.client.get('/grid/geometries/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Bulk Update Geometries
     * -------------
     *
     * Update in a Bulk list of Geometries.
     */
    bulkUpdateGeometries(body) {
        return this.client
            .put('/grid/geometries/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Geometry by Card
     * -------------
     *
     * Read a Geometry entity given the id of Card which is the parent of the Geometry entity.
     */
    readGeometryByCard(cardId) {
        return this.client.getDataState(`/grid/geometries/by_card/${cardId}`, { authorizationRequired: true });
    }
    readGeometryByCard2(cardId) {
        return this.client.get(`/grid/geometries/by_card/${cardId}`, { authorizationRequired: true });
    }
    /**
     * Read Graph
     * -------------
     *
     * Render and read Graph made out of all Cards and Links belonging to a given user.
     */
    readGraph(params) {
        return this.client.getDataState('/grid/graphs/', { params, authorizationRequired: true });
    }
    readGraph2(params) {
        return this.client.get('/grid/graphs/', { params, authorizationRequired: true });
    }
}
GeometriesDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
GeometriesDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class GossipDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Bulk Read all supported spoken languages
     */
    bulkReadSpeechLanguages() {
        return this.client.getDataState('/gossip/speech/languages/', { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadSpeechLanguages2() {
        return this.client.get('/gossip/speech/languages/', { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Bulk Read all supported voice languages
     */
    bulkReadTextLanguages() {
        return this.client.getDataState('/gossip/text/languages/', { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadTextLanguages2() {
        return this.client.get('/gossip/text/languages/', { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Detect spoken language
     */
    detectSpeechLanguages(body) {
        return this.client
            .post('/gossip/speech/detect_languages/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Detect written language
     */
    detectTextLanguages(body) {
        return this.client
            .post('/gossip/text/detect_languages/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
GossipDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
GossipDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class HashtagsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Hashtags
     * -------------
     *
     * Enables one to list a series of Hashtag instances. It accepts various query parameters such as: - `limit` - `offset` - `first_character`
     */
    bulkReadHashtags(params) {
        return this.client.getDataState('/hashtags/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadHashtags2(params) {
        return this.client.get('/hashtags/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Creating a single Hashtag
     * -------------
     *
     * Enables one to create a single Hashtag instance.
     */
    createHashtag(body) {
        return this.client
            .post('/hashtags/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Removing a single Hashtag
     * -------------
     *
     * Enables one to detach a single Hashtag instance from a list cards given by `card_ids`.
     */
    deleteHashtag(hashtagId, params) {
        return this.client
            .delete(`/hashtags/${hashtagId}`, { params, authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * List Hashtags TOC
     * -------------
     *
     * Enables one to list Hashtags Table of Contents made out of Hashtags. Note: Currently this endpoint returns only a flat list of hashtags with the count of Cards with which they're attached to. In the future though one could propose a mechanism which could calculate hierarchy between those hashtags (parent - child relationships) and ordering based on the knowledge grid topology. It accepts various query parameters such as: - `limit` - `offset`
     */
    readHashtagsToc(params) {
        return this.client.getDataState('/hashtags/toc/', { params, authorizationRequired: true });
    }
    readHashtagsToc2(params) {
        return this.client.get('/hashtags/toc/', { params, authorizationRequired: true });
    }
    /**
     * Updating a single Hashtag
     * -------------
     *
     * Enables one to update a single Hashtag instance with a list of `card_ids` to which it should get attached to.
     */
    updateHashtag(hashtagId, body) {
        return this.client
            .put(`/hashtags/${hashtagId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
HashtagsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
HashtagsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class InvoicesDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List all Invoices belonging to a given user
     * -------------
     *
     * Enables the the User to list all of the Invoices which were generated for his Donations or Subscription payments.
     */
    bulkReadInvoices() {
        return this.client.getDataState('/payments/invoices/', { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadInvoices2() {
        return this.client.get('/payments/invoices/', { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Calculate debt for a given user
     * -------------
     *
     * Calculate debt for a given user by searching for the latest unpaid invoice. It returns payment token which can be used in the PAID_WITH_DEFAULT_PAYMENT_CARD command
     */
    calculateDebt() {
        return this.client.getDataState('/payments/invoices/debt/', { authorizationRequired: true });
    }
    calculateDebt2() {
        return this.client.get('/payments/invoices/debt/', { authorizationRequired: true });
    }
}
InvoicesDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
InvoicesDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Invoice Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/invoice.py/#lines-53
 */
var BulkReadInvoicesResponseCurrency;
(function (BulkReadInvoicesResponseCurrency) {
    BulkReadInvoicesResponseCurrency["PLN"] = "PLN";
})(BulkReadInvoicesResponseCurrency || (BulkReadInvoicesResponseCurrency = {}));
var BulkReadInvoicesResponseProductType;
(function (BulkReadInvoicesResponseProductType) {
    BulkReadInvoicesResponseProductType["DONATION"] = "DONATION";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    BulkReadInvoicesResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(BulkReadInvoicesResponseProductType || (BulkReadInvoicesResponseProductType = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class LinksDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Remove Link
     * -------------
     *
     * Remove a Link between two cards.
     */
    deleteLink(fromCardId, toCardId) {
        return this.client
            .delete(`/grid/links/${fromCardId}/${toCardId}`, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read or Create Link
     * -------------
     *
     * Read or Create a Link between two cards.
     */
    readOrCreateLink(body) {
        return this.client
            .post('/grid/links/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
LinksDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
LinksDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/grid/serializers.py/#lines-8
 */
var ReadOrCreateLinkResponseKind;
(function (ReadOrCreateLinkResponseKind) {
    ReadOrCreateLinkResponseKind["CARD"] = "CARD";
    ReadOrCreateLinkResponseKind["FRAGMENT"] = "FRAGMENT";
    ReadOrCreateLinkResponseKind["HASHTAG"] = "HASHTAG";
    ReadOrCreateLinkResponseKind["PATH"] = "PATH";
    ReadOrCreateLinkResponseKind["TERM"] = "TERM";
})(ReadOrCreateLinkResponseKind || (ReadOrCreateLinkResponseKind = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class MediaitemsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List MediaItems
     * -------------
     *
     * List MediaItems
     */
    bulkReadMediaitems(params) {
        return this.client.getDataState('/mediaitems/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadMediaitems2(params) {
        return this.client.get('/mediaitems/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Remove MediaItem
     * -------------
     *
     * Remove MediaItem instance.
     */
    deleteMediaitem(mediaitemId, params) {
        return this.client
            .delete(`/mediaitems/${mediaitemId}`, { params, authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read MediaItem
     * -------------
     *
     * Read MediaItem
     */
    readMediaitem(mediaitemId) {
        return this.client.getDataState(`/mediaitems/${mediaitemId}`, { authorizationRequired: true });
    }
    readMediaitem2(mediaitemId) {
        return this.client.get(`/mediaitems/${mediaitemId}`, { authorizationRequired: true });
    }
    /**
     * Read By Process Id
     * -------------
     *
     * Read MediaItem by Process Id
     */
    readMediaitemByProcessId() {
        return this.client.getDataState('/mediaitems/by_process/(?P<process_id>[\w+\=]+)', { authorizationRequired: true });
    }
    readMediaitemByProcessId2() {
        return this.client.get('/mediaitems/by_process/(?P<process_id>[\w+\=]+)', { authorizationRequired: true });
    }
    /**
     * Read or Create MediaItem
     * -------------
     *
     * Read or Create MediaItem instance.
     */
    readOrCreateMediaitem(body) {
        return this.client
            .post('/mediaitems/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Update MediaItem
     * -------------
     *
     * Update MediaItem instance.
     */
    updateMediaitem(mediaitemId, body) {
        return this.client
            .put(`/mediaitems/${mediaitemId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Update MediaItem Representation
     * -------------
     *
     * Update given MediaItem with only the fields which are decided externally (using external services). Fields like: - `web_representations` - `thumbnail_uri` - `meta` - `text` All of those fields are computed in smarter way in order to make the MediaItem way better in a semantic sense. Those fields are perceived as the `representation` of a given MediaItem since they contains information about how to display a given MediaItem, how to understand it etc. It goes beyond the simple abstract data oriented representation (uri, extension etc.).
     */
    updateMediaitemRepresentation(mediaitemId, body) {
        return this.client
            .put(`/mediaitems/${mediaitemId}/representation/`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
MediaitemsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
MediaitemsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class NotificationsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Acknowledge Notification
     * -------------
     *
     * Acknowledge Notification
     */
    acknowledgeNotification(notificationId) {
        return this.client
            .put(`/notifications/${notificationId}/acknowledge/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * List Notifications
     * -------------
     *
     * List Notifications
     */
    bulkReadNotifications(params) {
        return this.client.getDataState('/notifications/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadNotifications2(params) {
        return this.client.get('/notifications/', { params, responseMap: 'data', authorizationRequired: true });
    }
}
NotificationsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
NotificationsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/3709b52e6d7c7399154582e8055c0e76139a4c00/cosphere_fragment_service/notification/serializers.py/#lines-46
 */
var BulkReadNotificationsResponseKind;
(function (BulkReadNotificationsResponseKind) {
    BulkReadNotificationsResponseKind["FRAGMENT_UPDATE"] = "FRAGMENT_UPDATE";
})(BulkReadNotificationsResponseKind || (BulkReadNotificationsResponseKind = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class NounsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Bulk Read Noun Project Icons
     */
    bulkReadIcons(params) {
        return this.client.getDataState('/nouns/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadIcons2(params) {
        return this.client.get('/nouns/', { params, responseMap: 'data', authorizationRequired: true });
    }
}
NounsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
NounsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class PathsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Delete Paths
     * -------------
     *
     * Endpoint for Deleting multiple Paths.
     */
    bulkDeletePaths(params) {
        return this.client
            .delete('/paths/', { params, authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * List Paths
     * -------------
     *
     * List all user's Paths
     */
    bulkReadPaths(params) {
        return this.client.getDataState('/paths/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadPaths2(params) {
        return this.client.get('/paths/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Create Path
     * -------------
     *
     * Endpoint for Creating Path.
     */
    createPath(body) {
        return this.client
            .post('/paths/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Path
     * -------------
     *
     * Read single Path
     */
    readPath(pathId) {
        return this.client.getDataState(`/paths/${pathId}`, { authorizationRequired: true });
    }
    readPath2(pathId) {
        return this.client.get(`/paths/${pathId}`, { authorizationRequired: true });
    }
    /**
     * Update Path
     * -------------
     *
     * Endpoint for Updating Path.
     */
    updatePath(pathId, body) {
        return this.client
            .put(`/paths/${pathId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
PathsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
PathsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class PaymentCardsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Mark a given Payment Card as a default one
     * -------------
     *
     * Enables the the User to mark a specific Payment Card as a default one, meaning that it will be used for all upcoming payments. Marking Payment Card as a default one automatically leads to the unmarking of any Payment Card which was default one before the invocation of the command.
     */
    asDefaultMarkPaymentcard(paymentCardId) {
        return this.client
            .put(`/payments/payment_cards/${paymentCardId}/mark_as_default/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * List all Payment Cards belonging to a given user
     * -------------
     *
     * Enables the the User to list all of the Payment Cards which were added by him / her. Among all returned Payment Cards there must be one and only one which is marked as **default**.
     */
    bulkReadPaymentcards() {
        return this.client.getDataState('/payments/payment_cards/', { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadPaymentcards2() {
        return this.client.get('/payments/payment_cards/', { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Create a Payment Card
     * -------------
     *
     * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on. Using the optional `mark_as_default` field one can mark just created Payment Card as the default one.
     */
    createPaymentcard(body) {
        return this.client
            .post('/payments/payment_cards/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Remove a given Payment Card belonging to a given user
     * -------------
     *
     * Enables the the User to remove a specific Payment Card which were added by him / her. Payment Card can be removed only if it's not a default one.
     */
    deletePaymentcard(paymentCardId) {
        return this.client
            .delete(`/payments/payment_cards/${paymentCardId}`, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Pay using the default Payment Card
     * -------------
     *
     * User is allowed only to perform payments against her default Payment Card. In other words on order to use a given Payment Card one has to mark is as default. Also one is not allowed to perform such payments freely and therefore we expect to get a `payment_token` inside which another piece of our system encoded allowed sum to be paid.
     */
    payWithDefaultPaymentCard(body) {
        return this.client
            .post('/payments/payment_cards/pay_with_default/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create a Payment Card
     * -------------
     *
     * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on
     */
    renderPaymentCardWidget() {
        return this.client.getDataState('/payments/payment_cards/widget/', { authorizationRequired: true });
    }
    renderPaymentCardWidget2() {
        return this.client.get('/payments/payment_cards/widget/', { authorizationRequired: true });
    }
}
PaymentCardsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
PaymentCardsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment_card.py/#lines-75
 */
var BulkReadPaymentcardsResponseCurrency;
(function (BulkReadPaymentcardsResponseCurrency) {
    BulkReadPaymentcardsResponseCurrency["PLN"] = "PLN";
})(BulkReadPaymentcardsResponseCurrency || (BulkReadPaymentcardsResponseCurrency = {}));
var BulkReadPaymentcardsResponseProductType;
(function (BulkReadPaymentcardsResponseProductType) {
    BulkReadPaymentcardsResponseProductType["DONATION"] = "DONATION";
    BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(BulkReadPaymentcardsResponseProductType || (BulkReadPaymentcardsResponseProductType = {}));
var BulkReadPaymentcardsResponseStatus;
(function (BulkReadPaymentcardsResponseStatus) {
    BulkReadPaymentcardsResponseStatus["CANCELED"] = "CANCELED";
    BulkReadPaymentcardsResponseStatus["COMPLETED"] = "COMPLETED";
    BulkReadPaymentcardsResponseStatus["NEW"] = "NEW";
    BulkReadPaymentcardsResponseStatus["PENDING"] = "PENDING";
    BulkReadPaymentcardsResponseStatus["REJECTED"] = "REJECTED";
})(BulkReadPaymentcardsResponseStatus || (BulkReadPaymentcardsResponseStatus = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment_card.py/#lines-9
 */
var CreatePaymentcardResponseCurrency;
(function (CreatePaymentcardResponseCurrency) {
    CreatePaymentcardResponseCurrency["PLN"] = "PLN";
})(CreatePaymentcardResponseCurrency || (CreatePaymentcardResponseCurrency = {}));
var CreatePaymentcardResponseProductType;
(function (CreatePaymentcardResponseProductType) {
    CreatePaymentcardResponseProductType["DONATION"] = "DONATION";
    CreatePaymentcardResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    CreatePaymentcardResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    CreatePaymentcardResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    CreatePaymentcardResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(CreatePaymentcardResponseProductType || (CreatePaymentcardResponseProductType = {}));
var CreatePaymentcardResponseStatus;
(function (CreatePaymentcardResponseStatus) {
    CreatePaymentcardResponseStatus["CANCELED"] = "CANCELED";
    CreatePaymentcardResponseStatus["COMPLETED"] = "COMPLETED";
    CreatePaymentcardResponseStatus["NEW"] = "NEW";
    CreatePaymentcardResponseStatus["PENDING"] = "PENDING";
    CreatePaymentcardResponseStatus["REJECTED"] = "REJECTED";
})(CreatePaymentcardResponseStatus || (CreatePaymentcardResponseStatus = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment.py/#lines-9
 */
var PayWithDefaultPaymentCardResponseCurrency;
(function (PayWithDefaultPaymentCardResponseCurrency) {
    PayWithDefaultPaymentCardResponseCurrency["PLN"] = "PLN";
})(PayWithDefaultPaymentCardResponseCurrency || (PayWithDefaultPaymentCardResponseCurrency = {}));
var PayWithDefaultPaymentCardResponseProductType;
(function (PayWithDefaultPaymentCardResponseProductType) {
    PayWithDefaultPaymentCardResponseProductType["DONATION"] = "DONATION";
    PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(PayWithDefaultPaymentCardResponseProductType || (PayWithDefaultPaymentCardResponseProductType = {}));
var PayWithDefaultPaymentCardResponseStatus;
(function (PayWithDefaultPaymentCardResponseStatus) {
    PayWithDefaultPaymentCardResponseStatus["CANCELED"] = "CANCELED";
    PayWithDefaultPaymentCardResponseStatus["COMPLETED"] = "COMPLETED";
    PayWithDefaultPaymentCardResponseStatus["NEW"] = "NEW";
    PayWithDefaultPaymentCardResponseStatus["PENDING"] = "PENDING";
    PayWithDefaultPaymentCardResponseStatus["REJECTED"] = "REJECTED";
})(PayWithDefaultPaymentCardResponseStatus || (PayWithDefaultPaymentCardResponseStatus = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class PaymentsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Update the status of a given Payment
     * -------------
     *
     * Update the Payment instance identified by the `session_id`. This command is for external use only therefore it doesn't expose internal ids of the payments but rather session id.
     */
    updatePaymentStatus(body) {
        return this.client
            .post('/payments/(?P<session_id>[\w\-]+)', body, { authorizationRequired: false })
            .pipe(filter(x => !isEmpty(x)));
    }
}
PaymentsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
PaymentsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class ProcessesDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Create Deletion Process
     */
    createDeletionProcess(body) {
        return this.client
            .post('/mediafiles/processes/deletions/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Download Process
     */
    createDownloadProcess(body) {
        return this.client
            .post('/mediafiles/processes/downloads/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Media Lock
     */
    createMediaLock(body) {
        return this.client
            .post('/mediafiles/locks/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Upload Process
     */
    createUploadProcess(body) {
        return this.client
            .post('/mediafiles/processes/uploads/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read invariants for a given uri
     */
    readInvariants(params) {
        return this.client.getDataState('/mediafiles/invariants/', { params, authorizationRequired: true });
    }
    readInvariants2(params) {
        return this.client.get('/mediafiles/invariants/', { params, authorizationRequired: true });
    }
    /**
     * Create Media Lock
     */
    readProcessState(params) {
        return this.client.getDataState('/mediafiles/processes/', { params, authorizationRequired: true });
    }
    readProcessState2(params) {
        return this.client.get('/mediafiles/processes/', { params, authorizationRequired: true });
    }
    /**
     * Sign Process dedicated to upload and conversion of media file
     */
    signProcess(params) {
        return this.client.getDataState('/mediafiles/processes/sign/', { params, authorizationRequired: true });
    }
    signProcess2(params) {
        return this.client.get('/mediafiles/processes/sign/', { params, authorizationRequired: true });
    }
    /**
     * Watch conversion status
     * -------------
     *
     * Endpoint called by the external conversion service.
     */
    watchConversionStatus(waiterId, params) {
        return this.client.getDataState(`/mediafiles/convert_processes/(?P<process_id>[0-9a-zA-Z\_\-\=]+)/${waiterId}`, { params, authorizationRequired: false });
    }
    watchConversionStatus2(waiterId, params) {
        return this.client.get(`/mediafiles/convert_processes/(?P<process_id>[0-9a-zA-Z\_\-\=]+)/${waiterId}`, { params, authorizationRequired: false });
    }
}
ProcessesDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
ProcessesDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class QuizzerDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Build Read Quiz Attempts
     */
    bulkReadQuizattempts(quizId) {
        return this.client.getDataState(`/quizzes/${quizId}/attempts/`, { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadQuizattempts2(quizId) {
        return this.client.get(`/quizzes/${quizId}/attempts/`, { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Bulk Read Quizzes
     */
    bulkReadQuizzes() {
        return this.client.getDataState('/quizzes/', { responseMap: 'data', authorizationRequired: true });
    }
    bulkReadQuizzes2() {
        return this.client.get('/quizzes/', { responseMap: 'data', authorizationRequired: true });
    }
    /**
     * Create Quiz
     */
    createQuiz(body) {
        return this.client
            .post('/quizzes/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Create Quiz Attempt
     */
    createQuizattempt(quizId, body) {
        return this.client
            .post(`/quizzes/${quizId}/attempts/`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Delete Quiz
     */
    deleteQuiz(quizId) {
        return this.client
            .delete(`/quizzes/${quizId}`, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Quiz
     */
    readQuiz(quizId) {
        return this.client.getDataState(`/quizzes/${quizId}`, { authorizationRequired: true });
    }
    readQuiz2(quizId) {
        return this.client.get(`/quizzes/${quizId}`, { authorizationRequired: true });
    }
    /**
     * Update Quiz
     */
    updateQuiz(quizId, body) {
        return this.client
            .put(`/quizzes/${quizId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
QuizzerDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
QuizzerDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class RecallDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Create Recall Session
     * -------------
     *
     * Render Recall Session composed out of the sequence of Cards that should be recalled in a given order. Based on the RecallAttempt stats recommend another Card to recall in order to maximize the recall speed and success rate.
     */
    createRecallSession(body) {
        return this.client
            .post('/recall/sessions/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
    /**
     * Read Recall Summary
     * -------------
     *
     * Read summary stats for cards and their recall_score for a given User.
     */
    readRecallSummary() {
        return this.client.getDataState('/recall/summary/', { authorizationRequired: true });
    }
    readRecallSummary2() {
        return this.client.get('/recall/summary/', { authorizationRequired: true });
    }
}
RecallDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
RecallDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class SubscriptionsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Request a subscription change
     * -------------
     *
     * Whenever the user wants to change her subscription it must happen through this endpoint. It's still possible that the subscription will change without user asking for it, but that can happen when downgrading due to missing payment.
     */
    changeSubscription(body) {
        return this.client
            .put('/payments/subscription/', body, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
SubscriptionsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
SubscriptionsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Subscription Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/views/subscription.py/#lines-28
 */
var ChangeSubscriptionBodySubscriptionType;
(function (ChangeSubscriptionBodySubscriptionType) {
    ChangeSubscriptionBodySubscriptionType["FREE"] = "FREE";
    ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
    ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
    ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
    ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
})(ChangeSubscriptionBodySubscriptionType || (ChangeSubscriptionBodySubscriptionType = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class TasksDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Tasks
     * -------------
     *
     * List tasks
     */
    bulkReadTasks(params) {
        return this.client.getDataState('/tasks/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadTasks2(params) {
        return this.client.get('/tasks/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * List Task Bins
     * -------------
     *
     * List Tasks Bins
     */
    bulkReadTaskBins(params) {
        return this.client.getDataState('/tasks/bins/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadTaskBins2(params) {
        return this.client.get('/tasks/bins/', { params, responseMap: 'data', authorizationRequired: true });
    }
}
TasksDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
TasksDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Tasks Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/views.py/#lines-33
 */
var BulkReadTasksQueryQueueType;
(function (BulkReadTasksQueryQueueType) {
    BulkReadTasksQueryQueueType["DN"] = "DN";
    BulkReadTasksQueryQueueType["HP"] = "HP";
    BulkReadTasksQueryQueueType["OT"] = "OT";
    BulkReadTasksQueryQueueType["PR"] = "PR";
})(BulkReadTasksQueryQueueType || (BulkReadTasksQueryQueueType = {}));
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/serializers.py/#lines-55
 */
var BulkReadTasksResponseQueueType;
(function (BulkReadTasksResponseQueueType) {
    BulkReadTasksResponseQueueType["DN"] = "DN";
    BulkReadTasksResponseQueueType["HP"] = "HP";
    BulkReadTasksResponseQueueType["OT"] = "OT";
    BulkReadTasksResponseQueueType["PR"] = "PR";
})(BulkReadTasksResponseQueueType || (BulkReadTasksResponseQueueType = {}));
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/views.py/#lines-33
 */
var BulkReadTaskBinsQueryQueueType;
(function (BulkReadTaskBinsQueryQueueType) {
    BulkReadTaskBinsQueryQueueType["DN"] = "DN";
    BulkReadTaskBinsQueryQueueType["HP"] = "HP";
    BulkReadTaskBinsQueryQueueType["OT"] = "OT";
    BulkReadTaskBinsQueryQueueType["PR"] = "PR";
})(BulkReadTaskBinsQueryQueueType || (BulkReadTaskBinsQueryQueueType = {}));
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/5f215fabba7fa3925151c098fad0051162452821/cosphere_entity_service/task/serializers.py/#lines-71
 */
var BulkReadTaskBinsResponseQueueType;
(function (BulkReadTaskBinsResponseQueueType) {
    BulkReadTaskBinsResponseQueueType["DN"] = "DN";
    BulkReadTaskBinsResponseQueueType["HP"] = "HP";
    BulkReadTaskBinsResponseQueueType["OT"] = "OT";
    BulkReadTaskBinsResponseQueueType["PR"] = "PR";
})(BulkReadTaskBinsResponseQueueType || (BulkReadTaskBinsResponseQueueType = {}));

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class WordsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Words
     * -------------
     *
     * List Words by first character. It allows one to fetch list of words by first character.
     */
    bulkReadWords(params) {
        return this.client.getDataState('/words/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadWords2(params) {
        return this.client.get('/words/', { params, responseMap: 'data', authorizationRequired: true });
    }
}
WordsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
WordsDomain.ctorParameters = () => [
    { type: ClientService }
];

/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
class APIService {
    constructor(injector) {
        this.injector = injector;
    }
    get account_settingsDomain() {
        if (!this._account_settingsDomain) {
            this._account_settingsDomain = this.injector.get(AccountSettingsDomain);
        }
        return this._account_settingsDomain;
    }
    readAccountsetting() {
        return this.account_settingsDomain.readAccountsetting();
    }
    readAccountsetting2() {
        return this.account_settingsDomain.readAccountsetting2();
    }
    updateAccountsetting(body) {
        return this.account_settingsDomain.updateAccountsetting(body);
    }
    get accountsDomain() {
        if (!this._accountsDomain) {
            this._accountsDomain = this.injector.get(AccountsDomain);
        }
        return this._accountsDomain;
    }
    activateAccount(body) {
        return this.accountsDomain.activateAccount(body);
    }
    bulkReadAccounts(params) {
        return this.accountsDomain.bulkReadAccounts(params);
    }
    bulkReadAccounts2(params) {
        return this.accountsDomain.bulkReadAccounts2(params);
    }
    changePassword(body) {
        return this.accountsDomain.changePassword(body);
    }
    createAccount(body) {
        return this.accountsDomain.createAccount(body);
    }
    readAccount() {
        return this.accountsDomain.readAccount();
    }
    readAccount2() {
        return this.accountsDomain.readAccount2();
    }
    resetPassword(body) {
        return this.accountsDomain.resetPassword(body);
    }
    sendAccountActivationEmail(body) {
        return this.accountsDomain.sendAccountActivationEmail(body);
    }
    sendResetPasswordEmail(body) {
        return this.accountsDomain.sendResetPasswordEmail(body);
    }
    updateAccount(body) {
        return this.accountsDomain.updateAccount(body);
    }
    get attempt_statsDomain() {
        if (!this._attempt_statsDomain) {
            this._attempt_statsDomain = this.injector.get(AttemptStatsDomain);
        }
        return this._attempt_statsDomain;
    }
    bulkReadAttemptstats(params) {
        return this.attempt_statsDomain.bulkReadAttemptstats(params);
    }
    bulkReadAttemptstats2(params) {
        return this.attempt_statsDomain.bulkReadAttemptstats2(params);
    }
    createAttemptstat(body) {
        return this.attempt_statsDomain.createAttemptstat(body);
    }
    createExternalAttemptStat(body) {
        return this.attempt_statsDomain.createExternalAttemptStat(body);
    }
    get attemptsDomain() {
        if (!this._attemptsDomain) {
            this._attemptsDomain = this.injector.get(AttemptsDomain);
        }
        return this._attemptsDomain;
    }
    bulkReadAttemptsByCards(cardId) {
        return this.attemptsDomain.bulkReadAttemptsByCards(cardId);
    }
    bulkReadAttemptsByCards2(cardId) {
        return this.attemptsDomain.bulkReadAttemptsByCards2(cardId);
    }
    createAttempt(body) {
        return this.attemptsDomain.createAttempt(body);
    }
    updateAttempt(attemptId, body) {
        return this.attemptsDomain.updateAttempt(attemptId, body);
    }
    get auth_tokensDomain() {
        if (!this._auth_tokensDomain) {
            this._auth_tokensDomain = this.injector.get(AuthTokensDomain);
        }
        return this._auth_tokensDomain;
    }
    authorizeAuthToken() {
        return this.auth_tokensDomain.authorizeAuthToken();
    }
    createAuthToken(body) {
        return this.auth_tokensDomain.createAuthToken(body);
    }
    createFacebookBasedAuthToken(body) {
        return this.auth_tokensDomain.createFacebookBasedAuthToken(body);
    }
    createFacebookBasedMobileAuthToken(body) {
        return this.auth_tokensDomain.createFacebookBasedMobileAuthToken(body);
    }
    createGoogleBasedAuthToken(body) {
        return this.auth_tokensDomain.createGoogleBasedAuthToken(body);
    }
    createGoogleBasedMobileAuthToken(body) {
        return this.auth_tokensDomain.createGoogleBasedMobileAuthToken(body);
    }
    updateAuthToken() {
        return this.auth_tokensDomain.updateAuthToken();
    }
    get bricksDomain() {
        if (!this._bricksDomain) {
            this._bricksDomain = this.injector.get(BricksDomain);
        }
        return this._bricksDomain;
    }
    bulkReadGameattempts(gameId) {
        return this.bricksDomain.bulkReadGameattempts(gameId);
    }
    bulkReadGameattempts2(gameId) {
        return this.bricksDomain.bulkReadGameattempts2(gameId);
    }
    bulkReadGames() {
        return this.bricksDomain.bulkReadGames();
    }
    bulkReadGames2() {
        return this.bricksDomain.bulkReadGames2();
    }
    createGame(body) {
        return this.bricksDomain.createGame(body);
    }
    createGameattempt(gameId, body) {
        return this.bricksDomain.createGameattempt(gameId, body);
    }
    deleteGame(gameId) {
        return this.bricksDomain.deleteGame(gameId);
    }
    readGame(gameId) {
        return this.bricksDomain.readGame(gameId);
    }
    readGame2(gameId) {
        return this.bricksDomain.readGame2(gameId);
    }
    updateGame(gameId, body) {
        return this.bricksDomain.updateGame(gameId, body);
    }
    get cardsDomain() {
        if (!this._cardsDomain) {
            this._cardsDomain = this.injector.get(CardsDomain);
        }
        return this._cardsDomain;
    }
    bulkDeleteCards(params) {
        return this.cardsDomain.bulkDeleteCards(params);
    }
    bulkReadCards(params) {
        return this.cardsDomain.bulkReadCards(params);
    }
    bulkReadCards2(params) {
        return this.cardsDomain.bulkReadCards2(params);
    }
    createCard(body) {
        return this.cardsDomain.createCard(body);
    }
    readCard(cardId) {
        return this.cardsDomain.readCard(cardId);
    }
    readCard2(cardId) {
        return this.cardsDomain.readCard2(cardId);
    }
    updateCard(cardId, body) {
        return this.cardsDomain.updateCard(cardId, body);
    }
    get categoriesDomain() {
        if (!this._categoriesDomain) {
            this._categoriesDomain = this.injector.get(CategoriesDomain);
        }
        return this._categoriesDomain;
    }
    bulkReadCategories() {
        return this.categoriesDomain.bulkReadCategories();
    }
    bulkReadCategories2() {
        return this.categoriesDomain.bulkReadCategories2();
    }
    get contactsDomain() {
        if (!this._contactsDomain) {
            this._contactsDomain = this.injector.get(ContactsDomain);
        }
        return this._contactsDomain;
    }
    createAnonymousContactAttempt(body) {
        return this.contactsDomain.createAnonymousContactAttempt(body);
    }
    sendAuthenticatedContactMessage(body) {
        return this.contactsDomain.sendAuthenticatedContactMessage(body);
    }
    verifyAnonymousContactAttempt(body) {
        return this.contactsDomain.verifyAnonymousContactAttempt(body);
    }
    get donationsDomain() {
        if (!this._donationsDomain) {
            this._donationsDomain = this.injector.get(DonationsDomain);
        }
        return this._donationsDomain;
    }
    checkIfCanAttemptDonation(params) {
        return this.donationsDomain.checkIfCanAttemptDonation(params);
    }
    checkIfCanAttemptDonation2(params) {
        return this.donationsDomain.checkIfCanAttemptDonation2(params);
    }
    createAnonymousDonation(body) {
        return this.donationsDomain.createAnonymousDonation(body);
    }
    createDonation(body) {
        return this.donationsDomain.createDonation(body);
    }
    createDonationattempt(body) {
        return this.donationsDomain.createDonationattempt(body);
    }
    get external_appsDomain() {
        if (!this._external_appsDomain) {
            this._external_appsDomain = this.injector.get(ExternalAppsDomain);
        }
        return this._external_appsDomain;
    }
    authorizeExternalAppAuthToken() {
        return this.external_appsDomain.authorizeExternalAppAuthToken();
    }
    createExternalAppAuthToken(body) {
        return this.external_appsDomain.createExternalAppAuthToken(body);
    }
    readExternalappconf(params) {
        return this.external_appsDomain.readExternalappconf(params);
    }
    readExternalappconf2(params) {
        return this.external_appsDomain.readExternalappconf2(params);
    }
    get focus_recordsDomain() {
        if (!this._focus_recordsDomain) {
            this._focus_recordsDomain = this.injector.get(FocusRecordsDomain);
        }
        return this._focus_recordsDomain;
    }
    createFocusrecord(body) {
        return this.focus_recordsDomain.createFocusrecord(body);
    }
    readFocusRecordSummary() {
        return this.focus_recordsDomain.readFocusRecordSummary();
    }
    readFocusRecordSummary2() {
        return this.focus_recordsDomain.readFocusRecordSummary2();
    }
    get fragment_hashtagsDomain() {
        if (!this._fragment_hashtagsDomain) {
            this._fragment_hashtagsDomain = this.injector.get(FragmentHashtagsDomain);
        }
        return this._fragment_hashtagsDomain;
    }
    bulkReadFragmentHashtags(params) {
        return this.fragment_hashtagsDomain.bulkReadFragmentHashtags(params);
    }
    bulkReadFragmentHashtags2(params) {
        return this.fragment_hashtagsDomain.bulkReadFragmentHashtags2(params);
    }
    bulkReadPublishedFragmentHashtags(params) {
        return this.fragment_hashtagsDomain.bulkReadPublishedFragmentHashtags(params);
    }
    bulkReadPublishedFragmentHashtags2(params) {
        return this.fragment_hashtagsDomain.bulkReadPublishedFragmentHashtags2(params);
    }
    get fragment_wordsDomain() {
        if (!this._fragment_wordsDomain) {
            this._fragment_wordsDomain = this.injector.get(FragmentWordsDomain);
        }
        return this._fragment_wordsDomain;
    }
    bulkReadFragmentWords(params) {
        return this.fragment_wordsDomain.bulkReadFragmentWords(params);
    }
    bulkReadFragmentWords2(params) {
        return this.fragment_wordsDomain.bulkReadFragmentWords2(params);
    }
    bulkReadPublishedFragmentWords(params) {
        return this.fragment_wordsDomain.bulkReadPublishedFragmentWords(params);
    }
    bulkReadPublishedFragmentWords2(params) {
        return this.fragment_wordsDomain.bulkReadPublishedFragmentWords2(params);
    }
    get fragmentsDomain() {
        if (!this._fragmentsDomain) {
            this._fragmentsDomain = this.injector.get(FragmentsDomain);
        }
        return this._fragmentsDomain;
    }
    bulkReadFragments(params) {
        return this.fragmentsDomain.bulkReadFragments(params);
    }
    bulkReadFragments2(params) {
        return this.fragmentsDomain.bulkReadFragments2(params);
    }
    bulkReadPublishedFragments(params) {
        return this.fragmentsDomain.bulkReadPublishedFragments(params);
    }
    bulkReadPublishedFragments2(params) {
        return this.fragmentsDomain.bulkReadPublishedFragments2(params);
    }
    createFragment() {
        return this.fragmentsDomain.createFragment();
    }
    deleteFragment(fragmentId) {
        return this.fragmentsDomain.deleteFragment(fragmentId);
    }
    mergeFragment(fragmentId) {
        return this.fragmentsDomain.mergeFragment(fragmentId);
    }
    publishFragment(fragmentId) {
        return this.fragmentsDomain.publishFragment(fragmentId);
    }
    readFragment(fragmentId) {
        return this.fragmentsDomain.readFragment(fragmentId);
    }
    readFragment2(fragmentId) {
        return this.fragmentsDomain.readFragment2(fragmentId);
    }
    readFragmentDiff(fragmentId) {
        return this.fragmentsDomain.readFragmentDiff(fragmentId);
    }
    readFragmentDiff2(fragmentId) {
        return this.fragmentsDomain.readFragmentDiff2(fragmentId);
    }
    readFragmentSample(fragmentId) {
        return this.fragmentsDomain.readFragmentSample(fragmentId);
    }
    readFragmentSample2(fragmentId) {
        return this.fragmentsDomain.readFragmentSample2(fragmentId);
    }
    updateFragment(fragmentId, body) {
        return this.fragmentsDomain.updateFragment(fragmentId, body);
    }
    get geometriesDomain() {
        if (!this._geometriesDomain) {
            this._geometriesDomain = this.injector.get(GeometriesDomain);
        }
        return this._geometriesDomain;
    }
    bulkReadGeometries(params) {
        return this.geometriesDomain.bulkReadGeometries(params);
    }
    bulkReadGeometries2(params) {
        return this.geometriesDomain.bulkReadGeometries2(params);
    }
    bulkUpdateGeometries(body) {
        return this.geometriesDomain.bulkUpdateGeometries(body);
    }
    readGeometryByCard(cardId) {
        return this.geometriesDomain.readGeometryByCard(cardId);
    }
    readGeometryByCard2(cardId) {
        return this.geometriesDomain.readGeometryByCard2(cardId);
    }
    readGraph(params) {
        return this.geometriesDomain.readGraph(params);
    }
    readGraph2(params) {
        return this.geometriesDomain.readGraph2(params);
    }
    get gossipDomain() {
        if (!this._gossipDomain) {
            this._gossipDomain = this.injector.get(GossipDomain);
        }
        return this._gossipDomain;
    }
    bulkReadSpeechLanguages() {
        return this.gossipDomain.bulkReadSpeechLanguages();
    }
    bulkReadSpeechLanguages2() {
        return this.gossipDomain.bulkReadSpeechLanguages2();
    }
    bulkReadTextLanguages() {
        return this.gossipDomain.bulkReadTextLanguages();
    }
    bulkReadTextLanguages2() {
        return this.gossipDomain.bulkReadTextLanguages2();
    }
    detectSpeechLanguages(body) {
        return this.gossipDomain.detectSpeechLanguages(body);
    }
    detectTextLanguages(body) {
        return this.gossipDomain.detectTextLanguages(body);
    }
    get hashtagsDomain() {
        if (!this._hashtagsDomain) {
            this._hashtagsDomain = this.injector.get(HashtagsDomain);
        }
        return this._hashtagsDomain;
    }
    bulkReadHashtags(params) {
        return this.hashtagsDomain.bulkReadHashtags(params);
    }
    bulkReadHashtags2(params) {
        return this.hashtagsDomain.bulkReadHashtags2(params);
    }
    createHashtag(body) {
        return this.hashtagsDomain.createHashtag(body);
    }
    deleteHashtag(hashtagId, params) {
        return this.hashtagsDomain.deleteHashtag(hashtagId, params);
    }
    readHashtagsToc(params) {
        return this.hashtagsDomain.readHashtagsToc(params);
    }
    readHashtagsToc2(params) {
        return this.hashtagsDomain.readHashtagsToc2(params);
    }
    updateHashtag(hashtagId, body) {
        return this.hashtagsDomain.updateHashtag(hashtagId, body);
    }
    get invoicesDomain() {
        if (!this._invoicesDomain) {
            this._invoicesDomain = this.injector.get(InvoicesDomain);
        }
        return this._invoicesDomain;
    }
    bulkReadInvoices() {
        return this.invoicesDomain.bulkReadInvoices();
    }
    bulkReadInvoices2() {
        return this.invoicesDomain.bulkReadInvoices2();
    }
    calculateDebt() {
        return this.invoicesDomain.calculateDebt();
    }
    calculateDebt2() {
        return this.invoicesDomain.calculateDebt2();
    }
    get linksDomain() {
        if (!this._linksDomain) {
            this._linksDomain = this.injector.get(LinksDomain);
        }
        return this._linksDomain;
    }
    deleteLink(fromCardId, toCardId) {
        return this.linksDomain.deleteLink(fromCardId, toCardId);
    }
    readOrCreateLink(body) {
        return this.linksDomain.readOrCreateLink(body);
    }
    get mediaitemsDomain() {
        if (!this._mediaitemsDomain) {
            this._mediaitemsDomain = this.injector.get(MediaitemsDomain);
        }
        return this._mediaitemsDomain;
    }
    bulkReadMediaitems(params) {
        return this.mediaitemsDomain.bulkReadMediaitems(params);
    }
    bulkReadMediaitems2(params) {
        return this.mediaitemsDomain.bulkReadMediaitems2(params);
    }
    deleteMediaitem(mediaitemId, params) {
        return this.mediaitemsDomain.deleteMediaitem(mediaitemId, params);
    }
    readMediaitem(mediaitemId) {
        return this.mediaitemsDomain.readMediaitem(mediaitemId);
    }
    readMediaitem2(mediaitemId) {
        return this.mediaitemsDomain.readMediaitem2(mediaitemId);
    }
    readMediaitemByProcessId() {
        return this.mediaitemsDomain.readMediaitemByProcessId();
    }
    readMediaitemByProcessId2() {
        return this.mediaitemsDomain.readMediaitemByProcessId2();
    }
    readOrCreateMediaitem(body) {
        return this.mediaitemsDomain.readOrCreateMediaitem(body);
    }
    updateMediaitem(mediaitemId, body) {
        return this.mediaitemsDomain.updateMediaitem(mediaitemId, body);
    }
    updateMediaitemRepresentation(mediaitemId, body) {
        return this.mediaitemsDomain.updateMediaitemRepresentation(mediaitemId, body);
    }
    get notificationsDomain() {
        if (!this._notificationsDomain) {
            this._notificationsDomain = this.injector.get(NotificationsDomain);
        }
        return this._notificationsDomain;
    }
    acknowledgeNotification(notificationId) {
        return this.notificationsDomain.acknowledgeNotification(notificationId);
    }
    bulkReadNotifications(params) {
        return this.notificationsDomain.bulkReadNotifications(params);
    }
    bulkReadNotifications2(params) {
        return this.notificationsDomain.bulkReadNotifications2(params);
    }
    get nounsDomain() {
        if (!this._nounsDomain) {
            this._nounsDomain = this.injector.get(NounsDomain);
        }
        return this._nounsDomain;
    }
    bulkReadIcons(params) {
        return this.nounsDomain.bulkReadIcons(params);
    }
    bulkReadIcons2(params) {
        return this.nounsDomain.bulkReadIcons2(params);
    }
    get pathsDomain() {
        if (!this._pathsDomain) {
            this._pathsDomain = this.injector.get(PathsDomain);
        }
        return this._pathsDomain;
    }
    bulkDeletePaths(params) {
        return this.pathsDomain.bulkDeletePaths(params);
    }
    bulkReadPaths(params) {
        return this.pathsDomain.bulkReadPaths(params);
    }
    bulkReadPaths2(params) {
        return this.pathsDomain.bulkReadPaths2(params);
    }
    createPath(body) {
        return this.pathsDomain.createPath(body);
    }
    readPath(pathId) {
        return this.pathsDomain.readPath(pathId);
    }
    readPath2(pathId) {
        return this.pathsDomain.readPath2(pathId);
    }
    updatePath(pathId, body) {
        return this.pathsDomain.updatePath(pathId, body);
    }
    get payment_cardsDomain() {
        if (!this._payment_cardsDomain) {
            this._payment_cardsDomain = this.injector.get(PaymentCardsDomain);
        }
        return this._payment_cardsDomain;
    }
    asDefaultMarkPaymentcard(paymentCardId) {
        return this.payment_cardsDomain.asDefaultMarkPaymentcard(paymentCardId);
    }
    bulkReadPaymentcards() {
        return this.payment_cardsDomain.bulkReadPaymentcards();
    }
    bulkReadPaymentcards2() {
        return this.payment_cardsDomain.bulkReadPaymentcards2();
    }
    createPaymentcard(body) {
        return this.payment_cardsDomain.createPaymentcard(body);
    }
    deletePaymentcard(paymentCardId) {
        return this.payment_cardsDomain.deletePaymentcard(paymentCardId);
    }
    payWithDefaultPaymentCard(body) {
        return this.payment_cardsDomain.payWithDefaultPaymentCard(body);
    }
    renderPaymentCardWidget() {
        return this.payment_cardsDomain.renderPaymentCardWidget();
    }
    renderPaymentCardWidget2() {
        return this.payment_cardsDomain.renderPaymentCardWidget2();
    }
    get paymentsDomain() {
        if (!this._paymentsDomain) {
            this._paymentsDomain = this.injector.get(PaymentsDomain);
        }
        return this._paymentsDomain;
    }
    updatePaymentStatus(body) {
        return this.paymentsDomain.updatePaymentStatus(body);
    }
    get processesDomain() {
        if (!this._processesDomain) {
            this._processesDomain = this.injector.get(ProcessesDomain);
        }
        return this._processesDomain;
    }
    createDeletionProcess(body) {
        return this.processesDomain.createDeletionProcess(body);
    }
    createDownloadProcess(body) {
        return this.processesDomain.createDownloadProcess(body);
    }
    createMediaLock(body) {
        return this.processesDomain.createMediaLock(body);
    }
    createUploadProcess(body) {
        return this.processesDomain.createUploadProcess(body);
    }
    readInvariants(params) {
        return this.processesDomain.readInvariants(params);
    }
    readInvariants2(params) {
        return this.processesDomain.readInvariants2(params);
    }
    readProcessState(params) {
        return this.processesDomain.readProcessState(params);
    }
    readProcessState2(params) {
        return this.processesDomain.readProcessState2(params);
    }
    signProcess(params) {
        return this.processesDomain.signProcess(params);
    }
    signProcess2(params) {
        return this.processesDomain.signProcess2(params);
    }
    watchConversionStatus(waiterId, params) {
        return this.processesDomain.watchConversionStatus(waiterId, params);
    }
    watchConversionStatus2(waiterId, params) {
        return this.processesDomain.watchConversionStatus2(waiterId, params);
    }
    get quizzerDomain() {
        if (!this._quizzerDomain) {
            this._quizzerDomain = this.injector.get(QuizzerDomain);
        }
        return this._quizzerDomain;
    }
    bulkReadQuizattempts(quizId) {
        return this.quizzerDomain.bulkReadQuizattempts(quizId);
    }
    bulkReadQuizattempts2(quizId) {
        return this.quizzerDomain.bulkReadQuizattempts2(quizId);
    }
    bulkReadQuizzes() {
        return this.quizzerDomain.bulkReadQuizzes();
    }
    bulkReadQuizzes2() {
        return this.quizzerDomain.bulkReadQuizzes2();
    }
    createQuiz(body) {
        return this.quizzerDomain.createQuiz(body);
    }
    createQuizattempt(quizId, body) {
        return this.quizzerDomain.createQuizattempt(quizId, body);
    }
    deleteQuiz(quizId) {
        return this.quizzerDomain.deleteQuiz(quizId);
    }
    readQuiz(quizId) {
        return this.quizzerDomain.readQuiz(quizId);
    }
    readQuiz2(quizId) {
        return this.quizzerDomain.readQuiz2(quizId);
    }
    updateQuiz(quizId, body) {
        return this.quizzerDomain.updateQuiz(quizId, body);
    }
    get recallDomain() {
        if (!this._recallDomain) {
            this._recallDomain = this.injector.get(RecallDomain);
        }
        return this._recallDomain;
    }
    createRecallSession(body) {
        return this.recallDomain.createRecallSession(body);
    }
    readRecallSummary() {
        return this.recallDomain.readRecallSummary();
    }
    readRecallSummary2() {
        return this.recallDomain.readRecallSummary2();
    }
    get subscriptionsDomain() {
        if (!this._subscriptionsDomain) {
            this._subscriptionsDomain = this.injector.get(SubscriptionsDomain);
        }
        return this._subscriptionsDomain;
    }
    changeSubscription(body) {
        return this.subscriptionsDomain.changeSubscription(body);
    }
    get tasksDomain() {
        if (!this._tasksDomain) {
            this._tasksDomain = this.injector.get(TasksDomain);
        }
        return this._tasksDomain;
    }
    bulkReadTasks(params) {
        return this.tasksDomain.bulkReadTasks(params);
    }
    bulkReadTasks2(params) {
        return this.tasksDomain.bulkReadTasks2(params);
    }
    bulkReadTaskBins(params) {
        return this.tasksDomain.bulkReadTaskBins(params);
    }
    bulkReadTaskBins2(params) {
        return this.tasksDomain.bulkReadTaskBins2(params);
    }
    get wordsDomain() {
        if (!this._wordsDomain) {
            this._wordsDomain = this.injector.get(WordsDomain);
        }
        return this._wordsDomain;
    }
    bulkReadWords(params) {
        return this.wordsDomain.bulkReadWords(params);
    }
    bulkReadWords2(params) {
        return this.wordsDomain.bulkReadWords2(params);
    }
}
APIService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
APIService.ctorParameters = () => [
    { type: Injector }
];

/**
* THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
* OVERWRITTEN
*/
class CoSphereClientModule {
    static forRoot(config) {
        return {
            ngModule: CoSphereClientModule,
            providers: [
                { provide: 'config', useValue: config }
            ]
        };
    }
}
CoSphereClientModule.decorators = [
    { type: NgModule, args: [{
                imports: [HttpClientModule],
                providers: [
                    ClientService,
                    // Domains
                    AccountSettingsDomain,
                    AccountsDomain,
                    AttemptStatsDomain,
                    AttemptsDomain,
                    AuthTokensDomain,
                    BricksDomain,
                    CardsDomain,
                    CategoriesDomain,
                    ContactsDomain,
                    DonationsDomain,
                    ExternalAppsDomain,
                    FocusRecordsDomain,
                    FragmentHashtagsDomain,
                    FragmentWordsDomain,
                    FragmentsDomain,
                    GeometriesDomain,
                    GossipDomain,
                    HashtagsDomain,
                    InvoicesDomain,
                    LinksDomain,
                    MediaitemsDomain,
                    NotificationsDomain,
                    NounsDomain,
                    PathsDomain,
                    PaymentCardsDomain,
                    PaymentsDomain,
                    ProcessesDomain,
                    QuizzerDomain,
                    RecallDomain,
                    SubscriptionsDomain,
                    TasksDomain,
                    WordsDomain,
                    // Facade
                    APIService,
                ]
            },] }
];

/**
 * Generated bundle index. Do not edit.
 */

export { CoSphereClientModule, ClientService, APIService, AccountSettingsDomain, AccountsDomain, BulkReadAccountsResponseAtype, ReadAccountResponseAtype, UpdateAccountResponseAtype, AttemptStatsDomain, AttemptsDomain, AuthTokensDomain, BricksDomain, CreateGameBodyAudioLanguage, CreateGameBodyLanguage, UpdateGameBodyAudioLanguage, UpdateGameBodyLanguage, CardsDomain, CategoriesDomain, BulkReadCategoriesResponseText, ContactsDomain, DonationsDomain, CheckIfCanAttemptDonationQueryEvent, CreateAnonymousDonationResponseCurrency, CreateAnonymousDonationResponseProductType, CreateAnonymousDonationResponseStatus, CreateDonationResponseCurrency, CreateDonationResponseProductType, CreateDonationResponseStatus, CreateDonationattemptBodyEvent, CreateDonationattemptResponseEvent, ExternalAppsDomain, FocusRecordsDomain, FragmentHashtagsDomain, FragmentWordsDomain, FragmentsDomain, GeometriesDomain, GossipDomain, HashtagsDomain, InvoicesDomain, BulkReadInvoicesResponseCurrency, BulkReadInvoicesResponseProductType, LinksDomain, ReadOrCreateLinkResponseKind, MediaitemsDomain, NotificationsDomain, BulkReadNotificationsResponseKind, NounsDomain, PathsDomain, PaymentCardsDomain, BulkReadPaymentcardsResponseCurrency, BulkReadPaymentcardsResponseProductType, BulkReadPaymentcardsResponseStatus, CreatePaymentcardResponseCurrency, CreatePaymentcardResponseProductType, CreatePaymentcardResponseStatus, PayWithDefaultPaymentCardResponseCurrency, PayWithDefaultPaymentCardResponseProductType, PayWithDefaultPaymentCardResponseStatus, PaymentsDomain, ProcessesDomain, QuizzerDomain, RecallDomain, SubscriptionsDomain, ChangeSubscriptionBodySubscriptionType, TasksDomain, BulkReadTasksQueryQueueType, BulkReadTasksResponseQueueType, BulkReadTaskBinsQueryQueueType, BulkReadTaskBinsResponseQueueType, WordsDomain };

//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29zcGhlcmUtY2xpZW50LmpzLm1hcCIsInNvdXJjZXMiOlsibmc6Ly9AY29zcGhlcmUvY2xpZW50L3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvYWNjb3VudF9zZXR0aW5ncy9hY2NvdW50X3NldHRpbmdzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2FjY291bnRzL2FjY291bnRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2FjY291bnRzL2FjY291bnRzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2F0dGVtcHRfc3RhdHMvYXR0ZW1wdF9zdGF0cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hdHRlbXB0cy9hdHRlbXB0cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hdXRoX3Rva2Vucy9hdXRoX3Rva2Vucy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9icmlja3MvYnJpY2tzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2JyaWNrcy9icmlja3MubW9kZWxzLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvY2FyZHMvY2FyZHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvY2F0ZWdvcmllcy9jYXRlZ29yaWVzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2NhdGVnb3JpZXMvY2F0ZWdvcmllcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9jb250YWN0cy9jb250YWN0cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9kb25hdGlvbnMvZG9uYXRpb25zLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2RvbmF0aW9ucy9kb25hdGlvbnMubW9kZWxzLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZXh0ZXJuYWxfYXBwcy9leHRlcm5hbF9hcHBzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ZvY3VzX3JlY29yZHMvZm9jdXNfcmVjb3Jkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9mcmFnbWVudF9oYXNodGFncy9mcmFnbWVudF9oYXNodGFncy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9mcmFnbWVudF93b3Jkcy9mcmFnbWVudF93b3Jkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9mcmFnbWVudHMvZnJhZ21lbnRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2dlb21ldHJpZXMvZ2VvbWV0cmllcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9nb3NzaXAvZ29zc2lwLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2hhc2h0YWdzL2hhc2h0YWdzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ludm9pY2VzL2ludm9pY2VzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ludm9pY2VzL2ludm9pY2VzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2xpbmtzL2xpbmtzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2xpbmtzL2xpbmtzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL21lZGlhaXRlbXMvbWVkaWFpdGVtcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9ub3RpZmljYXRpb25zL25vdGlmaWNhdGlvbnMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvbm90aWZpY2F0aW9ucy9ub3RpZmljYXRpb25zLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL25vdW5zL25vdW5zLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3BhdGhzL3BhdGhzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3BheW1lbnRfY2FyZHMvcGF5bWVudF9jYXJkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9wYXltZW50X2NhcmRzL3BheW1lbnRfY2FyZHMubW9kZWxzLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcGF5bWVudHMvcGF5bWVudHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcHJvY2Vzc2VzL3Byb2Nlc3Nlcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9xdWl6emVyL3F1aXp6ZXIuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcmVjYWxsL3JlY2FsbC5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9zdWJzY3JpcHRpb25zL3N1YnNjcmlwdGlvbnMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvc3Vic2NyaXB0aW9ucy9zdWJzY3JpcHRpb25zLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3Rhc2tzL3Rhc2tzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3Rhc2tzL3Rhc2tzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3dvcmRzL3dvcmRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9zZXJ2aWNlcy9hcGkuc2VydmljZS50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9jb3NwaGVyZS1jbGllbnQubW9kdWxlLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2Nvc3BoZXJlLWNsaWVudC50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBJbmplY3QgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7XG4gIEh0dHBDbGllbnQsXG4gIEh0dHBQYXJhbXMsXG4gIEh0dHBIZWFkZXJzLFxuICBIdHRwRXJyb3JSZXNwb25zZVxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBCZWhhdmlvclN1YmplY3QsIFN1YmplY3QsIE9ic2VydmFibGUsIHRocm93RXJyb3IgfSBmcm9tICdyeGpzJztcbmltcG9ydCB7IGNhdGNoRXJyb3IsIHJldHJ5LCBtYXAgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDb25maWcgfSBmcm9tICcuL2NvbmZpZy5zZXJ2aWNlJztcbmltcG9ydCB7IE9wdGlvbnMsIFN0YXRlLCBEYXRhU3RhdGUsIFJlcXVlc3RTdGF0ZSB9IGZyb20gJy4vY2xpZW50LmludGVyZmFjZSc7XG5cbkBJbmplY3RhYmxlKHtcbiAgcHJvdmlkZWRJbjogJ3Jvb3QnXG59KVxuZXhwb3J0IGNsYXNzIENsaWVudFNlcnZpY2Uge1xuICAvKipcbiAgICogU3RhdGUgZm9yIGFsbCBHRVQgcGF5bG9hZHNcbiAgICovXG4gIHN0YXRlID0gbmV3IE1hcDxzdHJpbmcsIFN0YXRlPGFueT4+KCk7XG5cbiAgcmVhZG9ubHkgYmFzZVVybDogc3RyaW5nO1xuICByZWFkb25seSBhdXRoVG9rZW46IHN0cmluZztcblxuICBwcml2YXRlIHJlYWRvbmx5IGRlZmF1bHRBdXRoVG9rZW46IHN0cmluZyA9ICdhdXRoX3Rva2VuJztcblxuICAvKipcbiAgICogQ2FjaGUgdGltZSAtIGV2ZXJ5IEdFVCByZXF1ZXN0IGlzIHRha2VuIG9ubHkgaWYgdGhlIGxhc3Qgb25lXG4gICAqIHdhcyBpbnZva2VkIG5vdCBlYXJsaWVyIHRoZW4gYGNhY2hlVGltZWAgbWlucyBhZ28uXG4gICAqIE9ubHkgc3VjY2Vzc2Z1bCByZXNwb25zZXMgYXJlIGNhY2hlZCAoMnh4KVxuICAgKi9cbiAgcHJpdmF0ZSByZWFkb25seSBjYWNoZVRpbWUgPSAxMDAwICogNjAgKiA2MDsgLy8gNjAgbWluc1xuXG4gIGNvbnN0cnVjdG9yKEBJbmplY3QoJ2NvbmZpZycpIHByaXZhdGUgY29uZmlnOiBDb25maWcsIHByaXZhdGUgaHR0cDogSHR0cENsaWVudCkge1xuICAgIHRoaXMuYmFzZVVybCA9IHRoaXMuY29uZmlnLmJhc2VVcmw7XG4gICAgdGhpcy5hdXRoVG9rZW4gPVxuICAgICAgdGhpcy5jb25maWcuYXV0aFRva2VuIHx8IHRoaXMuZGVmYXVsdEF1dGhUb2tlbjtcbiAgfVxuXG4gIGdldDxUPihlbmRwb2ludDogc3RyaW5nLCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLmdldCh1cmwsIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBwb3N0PFQ+KGVuZHBvaW50OiBzdHJpbmcsIGJvZHk6IGFueSwgb3B0aW9ucz86IE9wdGlvbnMpOiBPYnNlcnZhYmxlPFQ+IHtcbiAgICBjb25zdCB1cmwgPSB0aGlzLmdldFVybChlbmRwb2ludCk7XG4gICAgY29uc3QgaHR0cE9wdGlvbnMgPSB0aGlzLmdldEh0dHBPcHRpb25zKG9wdGlvbnMpO1xuICAgIHJldHVybiB0aGlzLmh0dHBcbiAgICAgIC5wb3N0KHVybCwgYm9keSwgaHR0cE9wdGlvbnMpXG4gICAgICAucGlwZShyZXRyeSgzKSwgY2F0Y2hFcnJvcih0aGlzLmhhbmRsZUVycm9yKSkgYXMgT2JzZXJ2YWJsZTxUPjtcbiAgfVxuXG4gIHB1dDxUPihlbmRwb2ludDogc3RyaW5nLCBib2R5OiBhbnksIG9wdGlvbnM/OiBPcHRpb25zKTogT2JzZXJ2YWJsZTxUPiB7XG4gICAgY29uc3QgdXJsID0gdGhpcy5nZXRVcmwoZW5kcG9pbnQpO1xuICAgIGNvbnN0IGh0dHBPcHRpb25zID0gdGhpcy5nZXRIdHRwT3B0aW9ucyhvcHRpb25zKTtcbiAgICByZXR1cm4gdGhpcy5odHRwXG4gICAgICAucHV0KHVybCwgYm9keSwgaHR0cE9wdGlvbnMpXG4gICAgICAucGlwZShyZXRyeSgzKSwgY2F0Y2hFcnJvcih0aGlzLmhhbmRsZUVycm9yKSkgYXMgT2JzZXJ2YWJsZTxUPjtcbiAgfVxuXG4gIGRlbGV0ZTxUPihlbmRwb2ludDogc3RyaW5nLCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLmRlbGV0ZSh1cmwsIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBnZXREYXRhU3RhdGU8VD4oZW5kcG9pbnQ6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiBEYXRhU3RhdGU8VD4ge1xuICAgIGNvbnN0IGtleSA9IG9wdGlvbnMgJiYgb3B0aW9ucy5wYXJhbXMgPyBgJHtlbmRwb2ludH1fJHtKU09OLnN0cmluZ2lmeShvcHRpb25zLnBhcmFtcyl9YCA6IGVuZHBvaW50O1xuICAgIHRoaXMuaW5pdFN0YXRlKGtleSwgb3B0aW9ucyk7XG5cbiAgICBsZXQgY2FjaGUgPSB0cnVlO1xuICAgIGxldCBwYXJhbXM6IEh0dHBQYXJhbXMgfCB7IFtwYXJhbTogc3RyaW5nXTogc3RyaW5nIHwgc3RyaW5nW10gfTtcblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAnY2FjaGUnKSkge1xuICAgICAgY2FjaGUgPSBvcHRpb25zLmNhY2hlO1xuICAgIH1cblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAncGFyYW1zJykpIHtcbiAgICAgIHBhcmFtcyA9IG9wdGlvbnMucGFyYW1zO1xuICAgIH1cblxuICAgIC8vIEdldCB0aGUgZW5kcG9pbnQgc3RhdGVcbiAgICBjb25zdCBzdGF0ZSA9IHRoaXMuc3RhdGUuZ2V0KGtleSk7XG5cbiAgICAvLyBEbyBub3QgYWxsb3cgaW52b2tlIHRoZSBzYW1lIEdFVCByZXF1ZXN0IHdoaWxlIG9uZSBpcyBwZW5kaW5nXG4gICAgaWYgKHN0YXRlLnJlcXVlc3RTdGF0ZS5wZW5kaW5nIC8qJiYgIV8uaXNFbXB0eShwYXJhbXMpKi8pIHtcbiAgICAgIHJldHVybiBzdGF0ZS5kYXRhU3RhdGU7XG4gICAgfVxuXG4gICAgY29uc3QgY3VycmVudFRpbWUgPSArbmV3IERhdGUoKTtcbiAgICBpZiAoXG4gICAgICBjdXJyZW50VGltZSAtIHN0YXRlLnJlcXVlc3RTdGF0ZS5jYWNoZWRBdCA+IHRoaXMuY2FjaGVUaW1lIHx8XG4gICAgICAvLyAhXy5pc0VtcHR5KHBhcmFtcykgfHxcbiAgICAgICFjYWNoZVxuICAgICkge1xuICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLnBlbmRpbmcgPSB0cnVlO1xuICAgICAgdGhpcy5nZXQoZW5kcG9pbnQsIG9wdGlvbnMpXG4gICAgICAgIC5waXBlKFxuICAgICAgICAgIG1hcChkYXRhID0+IChvcHRpb25zLnJlc3BvbnNlTWFwID8gZGF0YVtvcHRpb25zLnJlc3BvbnNlTWFwXSA6IGRhdGEpKVxuICAgICAgICApXG4gICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgZGF0YSA9PiB7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuZGF0YSQubmV4dChkYXRhKTtcbiAgICAgICAgICAgIHN0YXRlLmRhdGFTdGF0ZS5pc0RhdGEkLm5leHQoIV8uaXNFbXB0eShkYXRhKSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUubG9hZGluZyQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyA9IGZhbHNlO1xuICAgICAgICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLmNhY2hlZEF0ID0gY3VycmVudFRpbWU7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmlzRGF0YSQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuZGF0YSQuZXJyb3IobnVsbCk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUubG9hZGluZyQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyA9IGZhbHNlO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc3RhdGUuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQoZmFsc2UpO1xuICAgIH1cblxuICAgIHJldHVybiBzdGF0ZS5kYXRhU3RhdGU7XG4gIH1cblxuICBwcml2YXRlIGluaXRTdGF0ZShrZXk6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMuc3RhdGUuaGFzKGtleSkpIHtcbiAgICAgIHRoaXMuc3RhdGUuc2V0KGtleSwge1xuICAgICAgICBkYXRhU3RhdGU6IHtcbiAgICAgICAgICBsb2FkaW5nJDogbmV3IEJlaGF2aW9yU3ViamVjdCh0cnVlKSxcbiAgICAgICAgICBpc0RhdGEkOiBuZXcgQmVoYXZpb3JTdWJqZWN0KGZhbHNlKSxcbiAgICAgICAgICBkYXRhJDogbmV3IEJlaGF2aW9yU3ViamVjdChudWxsKVxuICAgICAgICB9LFxuICAgICAgICByZXF1ZXN0U3RhdGU6IHtcbiAgICAgICAgICBjYWNoZWRBdDogMCxcbiAgICAgICAgICBwZW5kaW5nOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5zdGF0ZS5nZXQoa2V5KS5kYXRhU3RhdGUubG9hZGluZyQubmV4dCh0cnVlKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGdldEh0dHBPcHRpb25zKFxuICAgIG9wdGlvbnM/OiBPcHRpb25zXG4gICk6IHtcbiAgICBwYXJhbXM/OiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgaGVhZGVycz86IEh0dHBIZWFkZXJzIHwgeyBbaGVhZGVyOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgIHJlcG9ydFByb2dyZXNzPzogYm9vbGVhbjtcbiAgfSB7XG4gICAgY29uc3QgYXV0aG9yaXphdGlvblJlcXVpcmVkID0gXy5oYXMob3B0aW9ucywgJ2F1dGhvcml6YXRpb25SZXF1aXJlZCcpXG4gICAgICA/IG9wdGlvbnMuYXV0aG9yaXphdGlvblJlcXVpcmVkXG4gICAgICA6IHRydWU7XG4gICAgY29uc3QgZXRhZyA9IChvcHRpb25zICYmIG9wdGlvbnMuZXRhZykgfHwgdW5kZWZpbmVkO1xuXG4gICAgbGV0IGh0dHBPcHRpb25zOiB7XG4gICAgICBwYXJhbXM/OiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgICBoZWFkZXJzPzogSHR0cEhlYWRlcnMgfCB7IFtoZWFkZXI6IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgICByZXBvcnRQcm9ncmVzcz86IGJvb2xlYW47XG4gICAgfSA9IHtcbiAgICAgIGhlYWRlcnM6IHRoaXMuZ2V0SGVhZGVycyhhdXRob3JpemF0aW9uUmVxdWlyZWQsIGV0YWcpXG4gICAgfTtcblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAnaGVhZGVycycpKSB7XG4gICAgICAvLyB0c2xpbnQ6ZGlzYWJsZVxuICAgICAgZm9yIChsZXQga2V5IGluIG9wdGlvbnMuaGVhZGVycykge1xuICAgICAgICBodHRwT3B0aW9ucy5oZWFkZXJzW2tleV0gPSAoPGFueT5vcHRpb25zKS5oZWFkZXJzW2tleV07XG4gICAgICB9XG4gICAgICAvLyB0c2xpbnQ6ZW5hYmxlXG4gICAgfVxuXG4gICAgaWYgKF8uaGFzKG9wdGlvbnMsICdwYXJhbXMnKSkge1xuICAgICAgaHR0cE9wdGlvbnMucGFyYW1zID0gb3B0aW9ucy5wYXJhbXM7XG4gICAgfVxuXG4gICAgaWYgKF8uaGFzKG9wdGlvbnMsICdyZXBvcnRQcm9ncmVzcycpKSB7XG4gICAgICBodHRwT3B0aW9ucy5yZXBvcnRQcm9ncmVzcyA9IG9wdGlvbnMucmVwb3J0UHJvZ3Jlc3M7XG4gICAgfVxuXG4gICAgcmV0dXJuIGh0dHBPcHRpb25zO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRIZWFkZXJzKFxuICAgIGF1dGhvcml6YXRpb25SZXF1aXJlZDogYm9vbGVhbixcbiAgICBldGFnPzogc3RyaW5nXG4gICk6IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH0ge1xuICAgIGxldCBoZWFkZXJzID0ge1xuICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJ1xuICAgIH07XG5cbiAgICBpZiAoYXV0aG9yaXphdGlvblJlcXVpcmVkKSB7XG4gICAgICBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSBgQmVhcmVyICR7dGhpcy5nZXRUb2tlbigpfWA7XG4gICAgfVxuXG4gICAgaWYgKGV0YWcpIHtcbiAgICAgIGhlYWRlcnNbJ0VUYWcnXSA9IGV0YWc7XG4gICAgfVxuXG4gICAgcmV0dXJuIGhlYWRlcnM7XG4gIH1cblxuICBwcml2YXRlIGdldFVybChlbmRwb2ludDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5iYXNlVXJsfSR7ZW5kcG9pbnR9YDtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0VG9rZW4oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0odGhpcy5hdXRoVG9rZW4pO1xuICB9XG5cbiAgcHJpdmF0ZSBoYW5kbGVFcnJvcihlcnJvcjogSHR0cEVycm9yUmVzcG9uc2UpIHtcbiAgICBpZiAoZXJyb3IuZXJyb3IgaW5zdGFuY2VvZiBFcnJvckV2ZW50KSB7XG4gICAgICAvLyBBIGNsaWVudC1zaWRlIG9yIG5ldHdvcmsgZXJyb3Igb2NjdXJyZWQuIEhhbmRsZSBpdCBhY2NvcmRpbmdseS5cbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0FuIGVycm9yIG9jY3VycmVkOicsIGVycm9yLmVycm9yLm1lc3NhZ2UpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBUaGUgYmFja2VuZCByZXR1cm5lZCBhbiB1bnN1Y2Nlc3NmdWwgcmVzcG9uc2UgY29kZS5cbiAgICAgIC8vIFRoZSByZXNwb25zZSBib2R5IG1heSBjb250YWluIGNsdWVzIGFzIHRvIHdoYXQgd2VudCB3cm9uZyxcbiAgICAgIGNvbnNvbGUuZXJyb3IoXG4gICAgICAgIGBCYWNrZW5kIHJldHVybmVkIGNvZGUgJHtlcnJvci5zdGF0dXN9LCBgICsgYGJvZHkgd2FzOiAke2Vycm9yLmVycm9yfWBcbiAgICAgICk7XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGFuIG9ic2VydmFibGUgd2l0aCBhIHVzZXItZmFjaW5nIGVycm9yIG1lc3NhZ2VcbiAgICByZXR1cm4gdGhyb3dFcnJvcignU29tZXRoaW5nIGJhZCBoYXBwZW5lZDsgcGxlYXNlIHRyeSBhZ2FpbiBsYXRlci4nKTtcbiAgfVxufVxuIiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBY2NvdW50IFNldHRpbmdzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2FjY291bnRfc2V0dGluZ3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEFjY291bnRTZXR0aW5nc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEFjY291bnQgU2V0dGluZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEFjY291bnRzZXR0aW5nKCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4oJy9hY2NvdW50L3NldHRpbmdzLycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEFjY291bnRzZXR0aW5nMigpOiBPYnNlcnZhYmxlPFguUmVhZEFjY291bnRzZXR0aW5nUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPignL2FjY291bnQvc2V0dGluZ3MvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIEFjY291bnQgU2V0dGluZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQWNjb3VudHNldHRpbmcoYm9keTogWC5VcGRhdGVBY2NvdW50c2V0dGluZ0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPignL2FjY291bnQvc2V0dGluZ3MvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEFjY291bnRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2FjY291bnRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBY2NvdW50c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBY3RpdmF0ZSBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQWN0aXZhdGUgQWNjb3VudCBieSBkZWNvZGluZyB0aGUgYGNvZGVgIHdoaWNoIGNvbnRhaW5zIHRoZSBjb25maXJtYXRpb24gb2ZmIHRoZSBpbnRlbnQgYW5kIHdhcyBzaWduZWQgYnkgdGhlIHVzZXIgaXRzZWxmLlxuICAgICAqL1xuICAgIHB1YmxpYyBhY3RpdmF0ZUFjY291bnQoYm9keTogWC5BY3RpdmF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkFjdGl2YXRlQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5BY3RpdmF0ZUFjY291bnRSZXNwb25zZT4oJy9hdXRoL2FjdGl2YXRlLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBNZW50b3JzJyBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlIG9uZSB0byBSZWFkIGFsbCBhdmFpbGFibGUgTWVudG9yIGFjY291bnRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQWNjb3VudHMocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9hdXRoL2FjY291bnRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEFjY291bnRzMihwYXJhbXM6IFguQnVsa1JlYWRBY2NvdW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9hdXRoL2FjY291bnRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2hhbmdlIFBhc3N3b3JkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY2hhbmdlIG9uZSdzIHBhc3N3b3JkIGZvciBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIGNoYW5nZVBhc3N3b3JkKGJvZHk6IFguQ2hhbmdlUGFzc3dvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNoYW5nZVBhc3N3b3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNoYW5nZVBhc3N3b3JkUmVzcG9uc2U+KCcvYXV0aC9jaGFuZ2VfcGFzc3dvcmQvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZXMgVXNlciBhbmQgQWNjb3VudCBpZiBwcm92aWRlZCBkYXRhIGFyZSB2YWxpZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQWNjb3VudChib2R5OiBYLkNyZWF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlQWNjb3VudFJlc3BvbnNlPignL2F1dGgvYWNjb3VudHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBNeSBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBteSBBY2NvdW50IGRhdGEuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRBY2NvdW50KCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY2NvdW50cy9tZS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRBY2NvdW50MigpOiBPYnNlcnZhYmxlPFguUmVhZEFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEFjY291bnRSZXNwb25zZT4oJy9hdXRoL2FjY291bnRzL21lLycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlc2V0IFBhc3N3b3JkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gcmVzZXQgaGVyIHBhc3N3b3JkIGluIGNhc2UgdGhlIG9sZCBvbmUgY2Fubm90IGJlIHJlY2FsbGVkLlxuICAgICAqL1xuICAgIHB1YmxpYyByZXNldFBhc3N3b3JkKGJvZHk6IFguUmVzZXRQYXNzd29yZEJvZHkpOiBPYnNlcnZhYmxlPFguUmVzZXRQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5SZXNldFBhc3N3b3JkUmVzcG9uc2U+KCcvYXV0aC9yZXNldF9wYXNzd29yZC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTZW5kIEFjY291bnQgQWN0aXZhdGlvbiBFbWFpbFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNlbmQgYW4gRW1haWwgY29udGFpbmluZyB0aGUgY29uZmlybWF0aW9uIGxpbmsgd2hpY2ggd2hlbiBjbGlja2VkIGtpY2tzIG9mIHRoZSBBY2NvdW50IEFjdGl2YXRpb24uIEV2ZW4gdGhvdWdoIHRoZSBhY3RpdmF0aW9uIGVtYWlsIGlzIHNlbmQgYXV0b21hdGljYWxseSBkdXJpbmcgdGhlIFNpZ24gVXAgcGhhc2Ugb25lIHNob3VsZCBoYXZlIGEgd2F5IHRvIHNlbmQgaXQgYWdhaW4gaW4gY2FzZSBpdCB3YXMgbm90IGRlbGl2ZXJlZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgc2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWwoYm9keTogWC5TZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxSZXNwb25zZT4oJy9hdXRoL3NlbmRfYWN0aXZhdGlvbl9lbWFpbC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTZW5kIFJlc2V0IFBhc3N3b3JkIEVtYWlsXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2VuZCBhbiBFbWFpbCBjb250YWluaW5nIHRoZSBjb25maXJtYXRpb24gbGluayB3aGljaCB3aGVuIGNsaWNrZWQga2lja3Mgb2YgdGhlIHJlYWwgUmVzZXQgUGFzc3dvcmQgb3BlcmF0aW9uLlxuICAgICAqL1xuICAgIHB1YmxpYyBzZW5kUmVzZXRQYXNzd29yZEVtYWlsKGJvZHk6IFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5TZW5kUmVzZXRQYXNzd29yZEVtYWlsUmVzcG9uc2U+KCcvYXV0aC9zZW5kX3Jlc2V0X3Bhc3N3b3JkX2VtYWlsLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBNeSBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIG15IEFjY291bnQgZGF0YS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQWNjb3VudChib2R5OiBYLlVwZGF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY2NvdW50cy9tZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQWNjb3VudHMgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9hY3RpdmF0ZV9hY2NvdW50LnB5LyNsaW5lcy0xMDNcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEFjdGl2YXRlQWNjb3VudEJvZHkge1xuICAgIGNvZGU6IHN0cmluZztcbiAgICBlbWFpbDogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBBY3RpdmF0ZUFjY291bnRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2FjY291bnQucHkvI2xpbmVzLTE3OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRBY2NvdW50c1F1ZXJ5IHtcbiAgICB1c2VyX2lkczogbnVtYmVyW107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvc2VyaWFsaXplcnMucHkvI2xpbmVzLTIzXG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlQXR5cGUge1xuICAgIEFETUlOID0gJ0FETUlOJyxcbiAgICBGUkVFID0gJ0ZSRUUnLFxuICAgIExFQVJORVIgPSAnTEVBUk5FUicsXG4gICAgTUVOVE9SID0gJ01FTlRPUicsXG4gICAgUEFSVE5FUiA9ICdQQVJUTkVSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHkge1xuICAgIGF0eXBlPzogQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlQXR5cGU7XG4gICAgYXZhdGFyX3VyaT86IHN0cmluZztcbiAgICBzaG93X2luX3Jhbmtpbmc/OiBib29sZWFuO1xuICAgIHVzZXJfaWQ/OiBhbnk7XG4gICAgdXNlcm5hbWU/OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlIHtcbiAgICBhY2NvdW50czogQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvY2hhbmdlX3Bhc3N3b3JkLnB5LyNsaW5lcy0yNFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhbmdlUGFzc3dvcmRCb2R5IHtcbiAgICBwYXNzd29yZDogc3RyaW5nO1xuICAgIHBhc3N3b3JkX2FnYWluOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENoYW5nZVBhc3N3b3JkUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9hY2NvdW50LnB5LyNsaW5lcy0xMTRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUFjY291bnRCb2R5IHtcbiAgICBlbWFpbDogc3RyaW5nO1xuICAgIHBhc3N3b3JkOiBzdHJpbmc7XG4gICAgcGFzc3dvcmRfYWdhaW46IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlQWNjb3VudFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvc2VyaWFsaXplcnMucHkvI2xpbmVzLThcbiAqL1xuXG5leHBvcnQgZW51bSBSZWFkQWNjb3VudFJlc3BvbnNlQXR5cGUge1xuICAgIEFETUlOID0gJ0FETUlOJyxcbiAgICBGUkVFID0gJ0ZSRUUnLFxuICAgIExFQVJORVIgPSAnTEVBUk5FUicsXG4gICAgTUVOVE9SID0gJ01FTlRPUicsXG4gICAgUEFSVE5FUiA9ICdQQVJUTkVSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBSZWFkQWNjb3VudFJlc3BvbnNlIHtcbiAgICBhdHlwZT86IFJlYWRBY2NvdW50UmVzcG9uc2VBdHlwZTtcbiAgICBhdmF0YXJfdXJpPzogc3RyaW5nO1xuICAgIHNob3dfaW5fcmFua2luZz86IGJvb2xlYW47XG4gICAgdXNlcl9pZD86IGFueTtcbiAgICB1c2VybmFtZT86IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9yZXNldF9wYXNzd29yZC5weS8jbGluZXMtOTRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFJlc2V0UGFzc3dvcmRCb2R5IHtcbiAgICBjb2RlOiBzdHJpbmc7XG4gICAgZW1haWw6IHN0cmluZztcbiAgICBwYXNzd29yZDogc3RyaW5nO1xuICAgIHBhc3N3b3JkX2FnYWluOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvc2VyaWFsaXplcnMucHkvI2xpbmVzLTMwXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBSZXNldFBhc3N3b3JkUmVzcG9uc2Uge1xuICAgIHRva2VuOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvYWN0aXZhdGVfYWNjb3VudC5weS8jbGluZXMtNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsQm9keSB7XG4gICAgZW1haWw6IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL3Jlc2V0X3Bhc3N3b3JkLnB5LyNsaW5lcy0zMVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgU2VuZFJlc2V0UGFzc3dvcmRFbWFpbEJvZHkge1xuICAgIGVtYWlsOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFNlbmRSZXNldFBhc3N3b3JkRW1haWxSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2FjY291bnQucHkvI2xpbmVzLTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBVcGRhdGVBY2NvdW50Qm9keSB7XG4gICAgYXZhdGFyX3VyaT86IHN0cmluZztcbiAgICBzaG93X2luX3Jhbmtpbmc/OiBib29sZWFuO1xuICAgIHVzZXJuYW1lPzogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy04XG4gKi9cblxuZXhwb3J0IGVudW0gVXBkYXRlQWNjb3VudFJlc3BvbnNlQXR5cGUge1xuICAgIEFETUlOID0gJ0FETUlOJyxcbiAgICBGUkVFID0gJ0ZSRUUnLFxuICAgIExFQVJORVIgPSAnTEVBUk5FUicsXG4gICAgTUVOVE9SID0gJ01FTlRPUicsXG4gICAgUEFSVE5FUiA9ICdQQVJUTkVSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBVcGRhdGVBY2NvdW50UmVzcG9uc2Uge1xuICAgIGF0eXBlPzogVXBkYXRlQWNjb3VudFJlc3BvbnNlQXR5cGU7XG4gICAgYXZhdGFyX3VyaT86IHN0cmluZztcbiAgICBzaG93X2luX3Jhbmtpbmc/OiBib29sZWFuO1xuICAgIHVzZXJfaWQ/OiBhbnk7XG4gICAgdXNlcm5hbWU/OiBzdHJpbmc7XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBdHRlbXB0IFN0YXRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2F0dGVtcHRfc3RhdHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF0dGVtcHRTdGF0c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IEF0dGVtcHQgU3RhdHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IEF0dGVtcHQgU3RhdHMgYnkgZmlsdGVyaW5nIGV4aXN0aW5nIG9uZXMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQXR0ZW1wdHN0YXRzKHBhcmFtczogWC5CdWxrUmVhZEF0dGVtcHRzdGF0c1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdF9zdGF0cy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRBdHRlbXB0c3RhdHMyKHBhcmFtczogWC5CdWxrUmVhZEF0dGVtcHRzdGF0c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRfc3RhdHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgQXR0ZW1wdCBTdGF0XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQ3JlYXRlIEF0dGVtcHQgU3RhdCB3aGljaCBzdG9yZXMgaW5mb3JtYXRpb24gYWJvdXQgYmFzaXMgc3RhdGlzdGljcyBvZiBhIHBhcnRpY3VsYXIgcmVjYWxsIGF0dGVtcHQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUF0dGVtcHRzdGF0KGJvZHk6IFguQ3JlYXRlQXR0ZW1wdHN0YXRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUF0dGVtcHRzdGF0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUF0dGVtcHRzdGF0UmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRfc3RhdHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgRXh0ZXJuYWwgQXR0ZW1wdCBTdGF0XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQ3JlYXRlIEV4dGVybmFsIEF0dGVtcHQgU3RhdCBtZWFuaW5nIG9uZSB3aGljaCB3YXMgcmVuZGVyZWQgZWxzZXdoZXJlIGluIGFueSBvZiB0aGUgbXVsdGlwbGUgQ29TcGhlcmUgYXBwcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdChib2R5OiBYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdFJlc3BvbnNlPignL3JlY2FsbC9hdHRlbXB0X3N0YXRzL2V4dGVybmFsLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBdHRlbXB0cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hdHRlbXB0cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQXR0ZW1wdHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBBdHRlbXB0cyBCeSBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBBdHRlbXB0cyBmb3IgYSBzcGVjaWZpYyBDYXJkIGdpdmVuIGJ5IGl0cyBJZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHMoY2FyZElkOiBhbnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzUmVzcG9uc2VFbnRpdHlbXT4oYC9yZWNhbGwvYXR0ZW1wdHMvYnlfY2FyZC8ke2NhcmRJZH1gLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzMihjYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzUmVzcG9uc2VFbnRpdHlbXT4oYC9yZWNhbGwvYXR0ZW1wdHMvYnlfY2FyZC8ke2NhcmRJZH1gLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgQXR0ZW1wdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZSBBdHRlbXB0IHdoaWNoIGlzIGEgcmVmbGVjdGlvbiBvZiBzb21lb25lJ3Mga25vd2xlZGdlIHJlZ2FyZGluZyBhIGdpdmVuIENhcmQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUF0dGVtcHQoYm9keTogWC5DcmVhdGVBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUF0dGVtcHRSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgQXR0ZW1wdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSBleGlzdGluZyBBdHRlbXB0IHdpdGggbmV3IGNlbGxzIGFuZCAvIG9yIHN0eWxlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVBdHRlbXB0KGF0dGVtcHRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVBdHRlbXB0UmVzcG9uc2U+KGAvcmVjYWxsL2F0dGVtcHRzLyR7YXR0ZW1wdElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBdXRoIFRva2VucyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hdXRoX3Rva2Vucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQXV0aFRva2Vuc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBdXRob3JpemUgYSBnaXZlbiB0b2tlblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENhbiBiZSBjYWxsZWQgYnkgdGhlIEFQSSBHYXRld2F5IGluIG9yZGVyIHRvIGF1dGhvcml6ZSBldmVyeSByZXF1ZXN0IHVzaW5nIHByb3ZpZGVkIHRva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBhdXRob3JpemVBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLkF1dGhvcml6ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5BdXRob3JpemVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2F1dGhvcml6ZS8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2lnbiBJblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFZhbGlkYXRlcyBkYXRhIHByb3ZpZGVkIG9uIHRoZSBpbnB1dCBhbmQgaWYgc3VjY2Vzc2Z1bCByZXR1cm5zIGF1dGggdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEZhY2Vib29rIEF1dGggVG9rZW5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvZmFjZWJvb2svJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1vYmlsZSBGYWNlYm9vayBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2ZhY2Vib29rL21vYmlsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgR29vZ2xlIEF1dGggVG9rZW5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2dvb2dsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgTW9iaWxlIEdvb2dsZSBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlR29vZ2xlQmFzZWRNb2JpbGVBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9nb29nbGUvbW9iaWxlLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZnJlc2ggSldUIHRva2VuXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2hvdWxkIGJlIHVzZWQgd2hlbmV2ZXIgdG9rZW4gaXMgY2xvc2UgdG8gZXhwaXJ5IG9yIGlmIG9uZSBpcyByZXF1ZXN0ZWQgdG8gcmVmcmVzaCB0aGUgdG9rZW4gYmVjYXVzZSBmb3IgZXhhbXBsZSBhY2NvdW50IHR5cGUgd2FzIGNoYW5nZWQgYW5kIG5ldyB0b2tlbiBzaG91bGQgYmUgcmVxdWVzdGVkIHRvIHJlZmxlY3QgdGhhdCBjaGFuZ2UuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEJyaWNrcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9icmlja3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEJyaWNrc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgQnJpY2tzIEdhbWUgQXR0ZW1wdHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRHYW1lYXR0ZW1wdHMoZ2FtZUlkOiBhbnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEdhbWVhdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2FtZWF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4oYC9nYW1lcy8ke2dhbWVJZH0vYXR0ZW1wdHMvYCwgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEdhbWVhdHRlbXB0czIoZ2FtZUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRHYW1lYXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEdhbWVhdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+KGAvZ2FtZXMvJHtnYW1lSWR9L2F0dGVtcHRzL2AsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBHYW1lXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkR2FtZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRHYW1lc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2FtZXNSZXNwb25zZUVudGl0eVtdPignL2dhbWVzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRHYW1lczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkR2FtZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEdhbWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9nYW1lcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgR2FtZVxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVHYW1lKGJvZHk6IFguQ3JlYXRlR2FtZUJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVHYW1lUmVzcG9uc2U+KCcvZ2FtZXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgQnJpY2tzIEdhbWUgQXR0ZW1wdFxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVHYW1lYXR0ZW1wdChnYW1lSWQ6IGFueSwgYm9keTogWC5DcmVhdGVHYW1lYXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR2FtZWF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlR2FtZWF0dGVtcHRSZXNwb25zZT4oYC9nYW1lcy8ke2dhbWVJZH0vYXR0ZW1wdHMvYCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZWxldGUgR2FtZVxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVHYW1lKGdhbWVJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUdhbWVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVHYW1lUmVzcG9uc2U+KGAvZ2FtZXMvJHtnYW1lSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEdhbWVcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEdhbWUoZ2FtZUlkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkR2FtZVJlc3BvbnNlPihgL2dhbWVzLyR7Z2FtZUlkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEdhbWUyKGdhbWVJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRHYW1lUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRHYW1lUmVzcG9uc2U+KGAvZ2FtZXMvJHtnYW1lSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIEdhbWVcbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlR2FtZShnYW1lSWQ6IGFueSwgYm9keTogWC5VcGRhdGVHYW1lQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVHYW1lUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlR2FtZVJlc3BvbnNlPihgL2dhbWVzLyR7Z2FtZUlkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBCcmlja3MgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvY29zcGhlcmVfYXBwX2JyaWNrc19iZS9nYW1lL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy03MVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRHYW1lYXR0ZW1wdHNSZXNwb25zZUVudGl0eSB7XG4gICAgYXR0ZW1wdD86IE9iamVjdDtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGdhbWVfaWQ/OiBhbnk7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgc3RhcnRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgdXNlcl9pZDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkR2FtZWF0dGVtcHRzUmVzcG9uc2Uge1xuICAgIGF0dGVtcHRzOiBCdWxrUmVhZEdhbWVhdHRlbXB0c1Jlc3BvbnNlRW50aXR5W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hcHAtYnJpY2tzLWJlL3NyYy85ZGZlODYxNjhlY2MxYmVhYzBjZTIyYTZiYTIwMDE2M2YzMTdmZGJhL2Nvc3BoZXJlX2FwcF9icmlja3NfYmUvZ2FtZS9zZXJpYWxpemVycy5weS8jbGluZXMtMjVcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkR2FtZXNSZXNwb25zZUVudGl0eSB7XG4gICAgYnJpY2tzOiBPYmplY3Q7XG4gICAgY2F0ZWdvcmllczogT2JqZWN0O1xuICAgIGNoYWxsZW5nZT86IHN0cmluZztcbiAgICBpZD86IG51bWJlcjtcbiAgICB0ZXJtczogT2JqZWN0O1xuICAgIHRpdGxlOiBzdHJpbmc7XG4gICAgdXNlcl9pZDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkR2FtZXNSZXNwb25zZSB7XG4gICAgZ2FtZXM6IEJ1bGtSZWFkR2FtZXNSZXNwb25zZUVudGl0eVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXBwLWJyaWNrcy1iZS9zcmMvOWRmZTg2MTY4ZWNjMWJlYWMwY2UyMmE2YmEyMDAxNjNmMzE3ZmRiYS9jb3NwaGVyZV9hcHBfYnJpY2tzX2JlL2dhbWUvcGFyc2Vycy5weS8jbGluZXMtNTRcbiAqL1xuXG5leHBvcnQgZW51bSBDcmVhdGVHYW1lQm9keUF1ZGlvTGFuZ3VhZ2Uge1xuICAgIGN5ID0gJ2N5JyxcbiAgICBkYSA9ICdkYScsXG4gICAgZGUgPSAnZGUnLFxuICAgIGVuID0gJ2VuJyxcbiAgICBlcyA9ICdlcycsXG4gICAgZnIgPSAnZnInLFxuICAgIGlzID0gJ2lzJyxcbiAgICBpdCA9ICdpdCcsXG4gICAgamEgPSAnamEnLFxuICAgIGtvID0gJ2tvJyxcbiAgICBuYiA9ICduYicsXG4gICAgbmwgPSAnbmwnLFxuICAgIHBsID0gJ3BsJyxcbiAgICBwdCA9ICdwdCcsXG4gICAgcm8gPSAncm8nLFxuICAgIHJ1ID0gJ3J1JyxcbiAgICBzdiA9ICdzdicsXG4gICAgdHIgPSAndHInLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVHYW1lQm9keUxhbmd1YWdlIHtcbiAgICBhZiA9ICdhZicsXG4gICAgYW0gPSAnYW0nLFxuICAgIGFuID0gJ2FuJyxcbiAgICBhciA9ICdhcicsXG4gICAgYXMgPSAnYXMnLFxuICAgIGF6ID0gJ2F6JyxcbiAgICBiZSA9ICdiZScsXG4gICAgYmcgPSAnYmcnLFxuICAgIGJuID0gJ2JuJyxcbiAgICBiciA9ICdicicsXG4gICAgYnMgPSAnYnMnLFxuICAgIGNhID0gJ2NhJyxcbiAgICBjcyA9ICdjcycsXG4gICAgY3kgPSAnY3knLFxuICAgIGRhID0gJ2RhJyxcbiAgICBkZSA9ICdkZScsXG4gICAgZHogPSAnZHonLFxuICAgIGVsID0gJ2VsJyxcbiAgICBlbiA9ICdlbicsXG4gICAgZW8gPSAnZW8nLFxuICAgIGVzID0gJ2VzJyxcbiAgICBldCA9ICdldCcsXG4gICAgZXUgPSAnZXUnLFxuICAgIGZhID0gJ2ZhJyxcbiAgICBmaSA9ICdmaScsXG4gICAgZm8gPSAnZm8nLFxuICAgIGZyID0gJ2ZyJyxcbiAgICBnYSA9ICdnYScsXG4gICAgZ2wgPSAnZ2wnLFxuICAgIGd1ID0gJ2d1JyxcbiAgICBoZSA9ICdoZScsXG4gICAgaGkgPSAnaGknLFxuICAgIGhyID0gJ2hyJyxcbiAgICBodCA9ICdodCcsXG4gICAgaHUgPSAnaHUnLFxuICAgIGh5ID0gJ2h5JyxcbiAgICBpZCA9ICdpZCcsXG4gICAgaXMgPSAnaXMnLFxuICAgIGl0ID0gJ2l0JyxcbiAgICBqYSA9ICdqYScsXG4gICAganYgPSAnanYnLFxuICAgIGthID0gJ2thJyxcbiAgICBrayA9ICdraycsXG4gICAga20gPSAna20nLFxuICAgIGtuID0gJ2tuJyxcbiAgICBrbyA9ICdrbycsXG4gICAga3UgPSAna3UnLFxuICAgIGt5ID0gJ2t5JyxcbiAgICBsYSA9ICdsYScsXG4gICAgbGIgPSAnbGInLFxuICAgIGxvID0gJ2xvJyxcbiAgICBsdCA9ICdsdCcsXG4gICAgbHYgPSAnbHYnLFxuICAgIG1nID0gJ21nJyxcbiAgICBtayA9ICdtaycsXG4gICAgbWwgPSAnbWwnLFxuICAgIG1uID0gJ21uJyxcbiAgICBtciA9ICdtcicsXG4gICAgbXMgPSAnbXMnLFxuICAgIG10ID0gJ210JyxcbiAgICBuYiA9ICduYicsXG4gICAgbmUgPSAnbmUnLFxuICAgIG5sID0gJ25sJyxcbiAgICBubiA9ICdubicsXG4gICAgbm8gPSAnbm8nLFxuICAgIG9jID0gJ29jJyxcbiAgICBvciA9ICdvcicsXG4gICAgcGEgPSAncGEnLFxuICAgIHBsID0gJ3BsJyxcbiAgICBwcyA9ICdwcycsXG4gICAgcHQgPSAncHQnLFxuICAgIHF1ID0gJ3F1JyxcbiAgICBybyA9ICdybycsXG4gICAgcnUgPSAncnUnLFxuICAgIHJ3ID0gJ3J3JyxcbiAgICBzZSA9ICdzZScsXG4gICAgc2kgPSAnc2knLFxuICAgIHNrID0gJ3NrJyxcbiAgICBzbCA9ICdzbCcsXG4gICAgc3EgPSAnc3EnLFxuICAgIHNyID0gJ3NyJyxcbiAgICBzdiA9ICdzdicsXG4gICAgc3cgPSAnc3cnLFxuICAgIHRhID0gJ3RhJyxcbiAgICB0ZSA9ICd0ZScsXG4gICAgdGggPSAndGgnLFxuICAgIHRsID0gJ3RsJyxcbiAgICB0ciA9ICd0cicsXG4gICAgdWcgPSAndWcnLFxuICAgIHVrID0gJ3VrJyxcbiAgICB1ciA9ICd1cicsXG4gICAgdmkgPSAndmknLFxuICAgIHZvID0gJ3ZvJyxcbiAgICB3YSA9ICd3YScsXG4gICAgeGggPSAneGgnLFxuICAgIHpoID0gJ3poJyxcbiAgICB6dSA9ICd6dScsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlR2FtZUJvZHkge1xuICAgIGJyaWNrczoge1xuICAgICAgICBiYWNrZ3JvdW5kPzoge1xuICAgICAgICAgICAgYXVkaW9fbGFuZ3VhZ2U/OiBDcmVhdGVHYW1lQm9keUF1ZGlvTGFuZ3VhZ2U7XG4gICAgICAgICAgICBhdWRpb190ZXh0Pzogc3RyaW5nO1xuICAgICAgICAgICAgYXVkaW9fdXJpPzogc3RyaW5nO1xuICAgICAgICB9O1xuICAgICAgICBjYXRlZ29yeV9jaWQ6IG51bWJlcjtcbiAgICAgICAgY2F0ZWdvcnlfaWQ/OiBudW1iZXI7XG4gICAgICAgIGNpZDogbnVtYmVyO1xuICAgICAgICBmb3JlZ3JvdW5kPzoge1xuICAgICAgICAgICAgaW1hZ2VfdXJpPzogc3RyaW5nO1xuICAgICAgICAgICAgbGFuZ3VhZ2U/OiBDcmVhdGVHYW1lQm9keUxhbmd1YWdlO1xuICAgICAgICAgICAgdGV4dD86IHN0cmluZztcbiAgICAgICAgfTtcbiAgICAgICAgaWQ/OiBudW1iZXI7XG4gICAgICAgIHJlYXNvbj86IHN0cmluZztcbiAgICB9W107XG4gICAgY2F0ZWdvcmllczoge1xuICAgICAgICBjaWQ6IG51bWJlcjtcbiAgICAgICAgaWQ/OiBudW1iZXI7XG4gICAgICAgIHRleHQ6IHN0cmluZztcbiAgICB9W107XG4gICAgY2hhbGxlbmdlOiBzdHJpbmc7XG4gICAgdGl0bGU6IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvY29zcGhlcmVfYXBwX2JyaWNrc19iZS9nYW1lL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy03XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVHYW1lUmVzcG9uc2Uge1xuICAgIGJyaWNrczogT2JqZWN0O1xuICAgIGNhdGVnb3JpZXM6IE9iamVjdDtcbiAgICBjaGFsbGVuZ2U/OiBzdHJpbmc7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgdGVybXM6IE9iamVjdDtcbiAgICB0aXRsZTogc3RyaW5nO1xuICAgIHVzZXJfaWQ6IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvY29zcGhlcmVfYXBwX2JyaWNrc19iZS9nYW1lL3BhcnNlcnMucHkvI2xpbmVzLTcyXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVHYW1lYXR0ZW1wdEJvZHkge1xuICAgIGF0dGVtcHQ6IHtcbiAgICAgICAgYnJpY2tfaWQ6IG51bWJlcjtcbiAgICAgICAgY2F0ZWdvcnlfaWQ6IG51bWJlcjtcbiAgICB9W107XG4gICAgc3RhcnRfZGF0ZXRpbWU6IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvY29zcGhlcmVfYXBwX2JyaWNrc19iZS9nYW1lL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy00MVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlR2FtZWF0dGVtcHRSZXNwb25zZSB7XG4gICAgYXR0ZW1wdD86IE9iamVjdDtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGdhbWVfaWQ/OiBhbnk7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgc3RhcnRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgdXNlcl9pZDogbnVtYmVyO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXBwLWJyaWNrcy1iZS9zcmMvOWRmZTg2MTY4ZWNjMWJlYWMwY2UyMmE2YmEyMDAxNjNmMzE3ZmRiYS8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRGVsZXRlR2FtZVJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hcHAtYnJpY2tzLWJlL3NyYy85ZGZlODYxNjhlY2MxYmVhYzBjZTIyYTZiYTIwMDE2M2YzMTdmZGJhL2Nvc3BoZXJlX2FwcF9icmlja3NfYmUvZ2FtZS9zZXJpYWxpemVycy5weS8jbGluZXMtN1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVhZEdhbWVSZXNwb25zZSB7XG4gICAgYnJpY2tzOiBPYmplY3Q7XG4gICAgY2F0ZWdvcmllczogT2JqZWN0O1xuICAgIGNoYWxsZW5nZT86IHN0cmluZztcbiAgICBpZD86IG51bWJlcjtcbiAgICB0ZXJtczogT2JqZWN0O1xuICAgIHRpdGxlOiBzdHJpbmc7XG4gICAgdXNlcl9pZDogbnVtYmVyO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXBwLWJyaWNrcy1iZS9zcmMvOWRmZTg2MTY4ZWNjMWJlYWMwY2UyMmE2YmEyMDAxNjNmMzE3ZmRiYS9jb3NwaGVyZV9hcHBfYnJpY2tzX2JlL2dhbWUvcGFyc2Vycy5weS8jbGluZXMtNTRcbiAqL1xuXG5leHBvcnQgZW51bSBVcGRhdGVHYW1lQm9keUF1ZGlvTGFuZ3VhZ2Uge1xuICAgIGN5ID0gJ2N5JyxcbiAgICBkYSA9ICdkYScsXG4gICAgZGUgPSAnZGUnLFxuICAgIGVuID0gJ2VuJyxcbiAgICBlcyA9ICdlcycsXG4gICAgZnIgPSAnZnInLFxuICAgIGlzID0gJ2lzJyxcbiAgICBpdCA9ICdpdCcsXG4gICAgamEgPSAnamEnLFxuICAgIGtvID0gJ2tvJyxcbiAgICBuYiA9ICduYicsXG4gICAgbmwgPSAnbmwnLFxuICAgIHBsID0gJ3BsJyxcbiAgICBwdCA9ICdwdCcsXG4gICAgcm8gPSAncm8nLFxuICAgIHJ1ID0gJ3J1JyxcbiAgICBzdiA9ICdzdicsXG4gICAgdHIgPSAndHInLFxufVxuXG5leHBvcnQgZW51bSBVcGRhdGVHYW1lQm9keUxhbmd1YWdlIHtcbiAgICBhZiA9ICdhZicsXG4gICAgYW0gPSAnYW0nLFxuICAgIGFuID0gJ2FuJyxcbiAgICBhciA9ICdhcicsXG4gICAgYXMgPSAnYXMnLFxuICAgIGF6ID0gJ2F6JyxcbiAgICBiZSA9ICdiZScsXG4gICAgYmcgPSAnYmcnLFxuICAgIGJuID0gJ2JuJyxcbiAgICBiciA9ICdicicsXG4gICAgYnMgPSAnYnMnLFxuICAgIGNhID0gJ2NhJyxcbiAgICBjcyA9ICdjcycsXG4gICAgY3kgPSAnY3knLFxuICAgIGRhID0gJ2RhJyxcbiAgICBkZSA9ICdkZScsXG4gICAgZHogPSAnZHonLFxuICAgIGVsID0gJ2VsJyxcbiAgICBlbiA9ICdlbicsXG4gICAgZW8gPSAnZW8nLFxuICAgIGVzID0gJ2VzJyxcbiAgICBldCA9ICdldCcsXG4gICAgZXUgPSAnZXUnLFxuICAgIGZhID0gJ2ZhJyxcbiAgICBmaSA9ICdmaScsXG4gICAgZm8gPSAnZm8nLFxuICAgIGZyID0gJ2ZyJyxcbiAgICBnYSA9ICdnYScsXG4gICAgZ2wgPSAnZ2wnLFxuICAgIGd1ID0gJ2d1JyxcbiAgICBoZSA9ICdoZScsXG4gICAgaGkgPSAnaGknLFxuICAgIGhyID0gJ2hyJyxcbiAgICBodCA9ICdodCcsXG4gICAgaHUgPSAnaHUnLFxuICAgIGh5ID0gJ2h5JyxcbiAgICBpZCA9ICdpZCcsXG4gICAgaXMgPSAnaXMnLFxuICAgIGl0ID0gJ2l0JyxcbiAgICBqYSA9ICdqYScsXG4gICAganYgPSAnanYnLFxuICAgIGthID0gJ2thJyxcbiAgICBrayA9ICdraycsXG4gICAga20gPSAna20nLFxuICAgIGtuID0gJ2tuJyxcbiAgICBrbyA9ICdrbycsXG4gICAga3UgPSAna3UnLFxuICAgIGt5ID0gJ2t5JyxcbiAgICBsYSA9ICdsYScsXG4gICAgbGIgPSAnbGInLFxuICAgIGxvID0gJ2xvJyxcbiAgICBsdCA9ICdsdCcsXG4gICAgbHYgPSAnbHYnLFxuICAgIG1nID0gJ21nJyxcbiAgICBtayA9ICdtaycsXG4gICAgbWwgPSAnbWwnLFxuICAgIG1uID0gJ21uJyxcbiAgICBtciA9ICdtcicsXG4gICAgbXMgPSAnbXMnLFxuICAgIG10ID0gJ210JyxcbiAgICBuYiA9ICduYicsXG4gICAgbmUgPSAnbmUnLFxuICAgIG5sID0gJ25sJyxcbiAgICBubiA9ICdubicsXG4gICAgbm8gPSAnbm8nLFxuICAgIG9jID0gJ29jJyxcbiAgICBvciA9ICdvcicsXG4gICAgcGEgPSAncGEnLFxuICAgIHBsID0gJ3BsJyxcbiAgICBwcyA9ICdwcycsXG4gICAgcHQgPSAncHQnLFxuICAgIHF1ID0gJ3F1JyxcbiAgICBybyA9ICdybycsXG4gICAgcnUgPSAncnUnLFxuICAgIHJ3ID0gJ3J3JyxcbiAgICBzZSA9ICdzZScsXG4gICAgc2kgPSAnc2knLFxuICAgIHNrID0gJ3NrJyxcbiAgICBzbCA9ICdzbCcsXG4gICAgc3EgPSAnc3EnLFxuICAgIHNyID0gJ3NyJyxcbiAgICBzdiA9ICdzdicsXG4gICAgc3cgPSAnc3cnLFxuICAgIHRhID0gJ3RhJyxcbiAgICB0ZSA9ICd0ZScsXG4gICAgdGggPSAndGgnLFxuICAgIHRsID0gJ3RsJyxcbiAgICB0ciA9ICd0cicsXG4gICAgdWcgPSAndWcnLFxuICAgIHVrID0gJ3VrJyxcbiAgICB1ciA9ICd1cicsXG4gICAgdmkgPSAndmknLFxuICAgIHZvID0gJ3ZvJyxcbiAgICB3YSA9ICd3YScsXG4gICAgeGggPSAneGgnLFxuICAgIHpoID0gJ3poJyxcbiAgICB6dSA9ICd6dScsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgVXBkYXRlR2FtZUJvZHkge1xuICAgIGJyaWNrczoge1xuICAgICAgICBiYWNrZ3JvdW5kPzoge1xuICAgICAgICAgICAgYXVkaW9fbGFuZ3VhZ2U/OiBVcGRhdGVHYW1lQm9keUF1ZGlvTGFuZ3VhZ2U7XG4gICAgICAgICAgICBhdWRpb190ZXh0Pzogc3RyaW5nO1xuICAgICAgICAgICAgYXVkaW9fdXJpPzogc3RyaW5nO1xuICAgICAgICB9O1xuICAgICAgICBjYXRlZ29yeV9jaWQ6IG51bWJlcjtcbiAgICAgICAgY2F0ZWdvcnlfaWQ/OiBudW1iZXI7XG4gICAgICAgIGNpZDogbnVtYmVyO1xuICAgICAgICBmb3JlZ3JvdW5kPzoge1xuICAgICAgICAgICAgaW1hZ2VfdXJpPzogc3RyaW5nO1xuICAgICAgICAgICAgbGFuZ3VhZ2U/OiBVcGRhdGVHYW1lQm9keUxhbmd1YWdlO1xuICAgICAgICAgICAgdGV4dD86IHN0cmluZztcbiAgICAgICAgfTtcbiAgICAgICAgaWQ/OiBudW1iZXI7XG4gICAgICAgIHJlYXNvbj86IHN0cmluZztcbiAgICB9W107XG4gICAgY2F0ZWdvcmllczoge1xuICAgICAgICBjaWQ6IG51bWJlcjtcbiAgICAgICAgaWQ/OiBudW1iZXI7XG4gICAgICAgIHRleHQ6IHN0cmluZztcbiAgICB9W107XG4gICAgY2hhbGxlbmdlOiBzdHJpbmc7XG4gICAgdGl0bGU6IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvY29zcGhlcmVfYXBwX2JyaWNrc19iZS9nYW1lL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy03XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBVcGRhdGVHYW1lUmVzcG9uc2Uge1xuICAgIGJyaWNrczogT2JqZWN0O1xuICAgIGNhdGVnb3JpZXM6IE9iamVjdDtcbiAgICBjaGFsbGVuZ2U/OiBzdHJpbmc7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgdGVybXM6IE9iamVjdDtcbiAgICB0aXRsZTogc3RyaW5nO1xuICAgIHVzZXJfaWQ6IG51bWJlcjtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIENhcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2NhcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDYXJkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbW92ZSBsaXN0IG9mIENhcmRzIHNwZWNpZmllZCBieSB0aGVpciBpZHMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtEZWxldGVDYXJkcyhwYXJhbXM6IFguQnVsa0RlbGV0ZUNhcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+KCcvY2FyZHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBNdWx0aXBsZSBDYXJkc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3Qgc3Vic2V0IG9mIENhcmRzIGRlcGVuZGluZyBvbiB2YXJpb3VzIGZpbHRlcmluZyBmbGFncy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRDYXJkcyhwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPignL2NhcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZENhcmRzMihwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXJkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0aW5nIGEgc2luZ2xlIENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBjcmVhdGUgYSBzaW5nbGUgQ2FyZCBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQ2FyZChib2R5OiBYLkNyZWF0ZUNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlQ2FyZFJlc3BvbnNlPignL2NhcmRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBDYXJkIGJ5IElkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBDYXJkIGJ5IGBpZGAuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRDYXJkKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZENhcmRSZXNwb25zZT4oYC9jYXJkcy8ke2NhcmRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRDYXJkMihjYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkQ2FyZFJlc3BvbnNlPihgL2NhcmRzLyR7Y2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0aW5nIGEgc2luZ2xlIENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBjcmVhdGUgYSBzaW5nbGUgQ2FyZCBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQ2FyZChjYXJkSWQ6IGFueSwgYm9keTogWC5VcGRhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQ2FyZFJlc3BvbnNlPihgL2NhcmRzLyR7Y2FyZElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBDYXRlZ29yaWVzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2NhdGVnb3JpZXMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIENhdGVnb3JpZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBDYXRlZ29yaWVzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBDYXRlZ29yaWVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZENhdGVnb3JpZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXRlZ29yaWVzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRDYXRlZ29yaWVzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXRlZ29yaWVzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQ2F0ZWdvcmllcyBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjLzVmMjE1ZmFiYmE3ZmEzOTI1MTUxYzA5OGZhZDAwNTExNjI0NTI4MjEvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvY2F0ZWdvcnkvc2VyaWFsaXplcnMucHkvI2xpbmVzLTI3XG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VUZXh0IHtcbiAgICBGT1JHT1RURU4gPSAnRk9SR09UVEVOJyxcbiAgICBIT1QgPSAnSE9UJyxcbiAgICBOT1RfUkVDQUxMRUQgPSAnTk9UX1JFQ0FMTEVEJyxcbiAgICBQUk9CTEVNQVRJQyA9ICdQUk9CTEVNQVRJQycsXG4gICAgUkVDRU5UTFlfQURERUQgPSAnUkVDRU5UTFlfQURERUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBjb3VudDogbnVtYmVyO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIHRleHQ6IEJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlVGV4dDtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZSB7XG4gICAgY2F0ZWdvcmllczogQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXTtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIENvbnRhY3QgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vY29udGFjdHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIENvbnRhY3RzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBBbm9ueW1vdXMgQ29udGFjdCBBdHRlbXB0XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gc2VuZCBtZXNzYWdlcyB0byBDb1NwaGVyZSdzIHN1cHBvcnQgZXZlbiBpZiB0aGUgc2VuZGVyIGlzIG5vdCBhdXRoZW50aWNhdGVkLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLkNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPignL2NvbnRhY3RzL2Fub255bW91cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTZW5kIEF1dGhlbnRpY2F0ZWQgQ29udGFjdCBNZXNzYWdlXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2VuZCB0aGUgQ29udGFjdCBNZXNzYWdlIGltbWVkaWF0ZWx5IHNpbmNlIGl0J3MgYWxyZWFkeSBmb3IgYW4gZXhpc3RpbmcgYW5kIGF1dGhlbnRpY2F0ZWQgdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgc2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZShib2R5OiBYLlNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2VCb2R5KTogT2JzZXJ2YWJsZTxYLlNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2VSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguU2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZVJlc3BvbnNlPignL2NvbnRhY3RzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZ5IHRoZSBjb250YWN0IGF0dGVtcHRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBWZXJpZnkgdGhlIGNvcnJlY3RuZXNzIG9mIHByb3ZpZGVkIHZlcmlmaWNhdGlvbiBjb2RlIGFuZCBzZW5kIHRoZSBtZXNzYWdlIHRvIHRoZSBDb1NwaGVyZSdzIHN1cHBvcnQuIFRoaXMgbWVjaGFuaXNtIGlzIHVzZWQgZm9yIGFub255bW91cyB1c2VycyBvbmx5LlxuICAgICAqL1xuICAgIHB1YmxpYyB2ZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLlZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPignL2NvbnRhY3RzL2Fub255bW91cy92ZXJpZnkvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBEb25hdGlvbnMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZG9uYXRpb25zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBEb25hdGlvbnNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ2hlY2sgaWYgb25lIGNhbiBhdHRlbXB0IGEgcmVxdWVzdCBkaXNwbGF5aW5nIGRvbmF0aW9uXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2luY2Ugd2UgZG9uJ3Qgd2FudCB0byBvdmVyZmxvdyB1c2VyIHdpdGggdW5uZWNlc3NhcnkgcmVxdWVzdHMgZm9yIGhpbSBkb25hdGluZyB3ZSBkbyBpdCBpbiBhIHNtYXJ0ZXIgd2F5IHVzaW5nIHNldCBvZiBoZXVyaXN0aWNzIHRoYXQgdG9nZXRoZXIgaGVscCB1cyB0byBhbnN3ZXIgdGhlIGZvbGxvd2luZyBxdWVzdGlvbjogXCJJcyBpdCB0aGUgYmVzdCBtb21lbnQgdG8gYXNrIGZvciB0aGUgZG9uYXRpb24/XCIuIEN1cnJlbnRseSB3ZSB1c2UgdGhlIGZvbGxvd2luZyBoZXVyaXN0aWNzOiAtIGlzIGFjY291bnQgb2xkIGVub3VnaD8gLSB3aGV0aGVyIHVzZXIgcmVjZW50bHkgZG9uYXRlZCAtIHdoZXRoZXIgd2UgYXR0ZW1wdGVkIHJlY2VudGx5IHRvIHJlcXVlc3QgZG9uYXRpb24gZnJvbSB0aGUgdXNlciAtIGlmIHRoZSB1c2VyIGluIGEgZ29vZCBtb29kIChhZnRlciBkb2luZyBzb21lIHN1Y2Nlc3NmdWwgcmVjYWxscylcbiAgICAgKi9cbiAgICBwdWJsaWMgY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbihwYXJhbXM6IFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5KTogRGF0YVN0YXRlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL2Nhbl9hdHRlbXB0LycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBjaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uMihwYXJhbXM6IFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5KTogT2JzZXJ2YWJsZTxYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPignL3BheW1lbnRzL2RvbmF0aW9ucy9jYW5fYXR0ZW1wdC8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZ2lzdGVyIGFub255bW91cyBkb25hdGlvblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIE9uZSBjYW4gcGVyZm9ybSBhIGRvbmF0aW9uIHBheW1lbnQgZXZlbiBpZiBub3QgYmVpbmcgYW4gYXV0aGVudGljYXRlZCB1c2VyLiBFdmVuIGluIHRoYXQgY2FzZSB3ZSBjYW5ub3QgYWxsb3cgZnVsbCBhbm9ueW1pdHkgYW5kIHdlIG11c3QgcmVxdWlyZSBhdCBsZWFzdCBlbWFpbCBhZGRyZXNzIHRvIHNlbmQgaW5mb3JtYXRpb24gcmVnYXJkaW5nIHRoZSBzdGF0dXMgb2YgdGhlIHBheW1lbnQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFub255bW91c0RvbmF0aW9uKGJvZHk6IFguQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL3JlZ2lzdGVyX2Fub255bW91cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWdpc3RlciBkb25hdGlvbiBmcm9tIGF1dGhlbnRpY2F0ZWQgdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIE9uZSBjYW4gcGVyZm9ybSBhIGRvbmF0aW9uIHBheW1lbnQgZXZlbiBhcyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZURvbmF0aW9uKGJvZHk6IFguQ3JlYXRlRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZURvbmF0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL3JlZ2lzdGVyLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGRvbmF0aW9uIGF0dGVtcHQgZm9yIGF1dGhlbnRpY2F0ZWQgdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVhY2ggRG9uYXRpb24gQXR0ZW1wdCBzaG91bGQgYmUgZm9sbG93ZWQgYnkgY3JlYXRpb24gb2YgRG9uYXRpb24gQXR0ZW1wdCBtb2RlbCBpbnN0YW5jZSB0byByZWZsZWN0IHRoYXQgZmFjdC4gSXQgYWxsb3dzIG9uZSB0byB0cmFjayBob3cgbWFueSB0aW1lcyB3ZSBhc2tlZCBhIGNlcnRhaW4gdXNlciBhYm91dCB0aGUgZG9uYXRpb24gaW4gb3JkZXIgbm90IHRvIG92ZXJmbG93IHRoYXQgdXNlciB3aXRoIHRoZW0gYW5kIG5vdCB0byBiZSB0b28gYWdncmVzc2l2ZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRG9uYXRpb25hdHRlbXB0KGJvZHk6IFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL2F0dGVtcHRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBEb25hdGlvbnMgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9kb25hdGlvbi5weS8jbGluZXMtMzBcbiAqL1xuXG5leHBvcnQgZW51bSBDaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnlFdmVudCB7XG4gICAgQ0xPU0UgPSAnQ0xPU0UnLFxuICAgIFJFQ0FMTCA9ICdSRUNBTEwnLFxuICAgIFNUQVJUID0gJ1NUQVJUJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnkge1xuICAgIGV2ZW50OiBDaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnlFdmVudDtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9kb25hdGlvbi5weS8jbGluZXMtMzRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZSB7XG4gICAgY2FuX2F0dGVtcHQ6IGJvb2xlYW47XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvZG9uYXRpb24ucHkvI2xpbmVzLTE4NFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25Cb2R5IHtcbiAgICBhbW91bnQ6IG51bWJlcjtcbiAgICBlbWFpbDogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnQucHkvI2xpbmVzLTlcbiAqL1xuXG5leHBvcnQgZW51bSBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlQ3VycmVuY3kge1xuICAgIFBMTiA9ICdQTE4nLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZVN0YXR1cyB7XG4gICAgQ0FOQ0VMRUQgPSAnQ0FOQ0VMRUQnLFxuICAgIENPTVBMRVRFRCA9ICdDT01QTEVURUQnLFxuICAgIE5FVyA9ICdORVcnLFxuICAgIFBFTkRJTkcgPSAnUEVORElORycsXG4gICAgUkVKRUNURUQgPSAnUkVKRUNURUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2Uge1xuICAgIGFtb3VudDogc3RyaW5nO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICBwcm9kdWN0OiB7XG4gICAgICAgIGN1cnJlbmN5PzogQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3RfdHlwZTogQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgIH07XG4gICAgc3RhdHVzPzogQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZVN0YXR1cztcbiAgICBzdGF0dXNfbGVkZ2VyPzogT2JqZWN0O1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL2RvbmF0aW9uLnB5LyNsaW5lcy0xODRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZURvbmF0aW9uQm9keSB7XG4gICAgYW1vdW50OiBudW1iZXI7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvcGF5bWVudC5weS8jbGluZXMtOVxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVEb25hdGlvblJlc3BvbnNlU3RhdHVzIHtcbiAgICBDQU5DRUxFRCA9ICdDQU5DRUxFRCcsXG4gICAgQ09NUExFVEVEID0gJ0NPTVBMRVRFRCcsXG4gICAgTkVXID0gJ05FVycsXG4gICAgUEVORElORyA9ICdQRU5ESU5HJyxcbiAgICBSRUpFQ1RFRCA9ICdSRUpFQ1RFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlRG9uYXRpb25SZXNwb25zZSB7XG4gICAgYW1vdW50OiBzdHJpbmc7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgY3VycmVuY3k/OiBDcmVhdGVEb25hdGlvblJlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgcHJvZHVjdF90eXBlOiBDcmVhdGVEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgfTtcbiAgICBzdGF0dXM/OiBDcmVhdGVEb25hdGlvblJlc3BvbnNlU3RhdHVzO1xuICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvZG9uYXRpb24ucHkvI2xpbmVzLTE4NFxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHlFdmVudCB7XG4gICAgQ0xPU0UgPSAnQ0xPU0UnLFxuICAgIFJFQ0FMTCA9ICdSRUNBTEwnLFxuICAgIFNUQVJUID0gJ1NUQVJUJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVEb25hdGlvbmF0dGVtcHRCb2R5IHtcbiAgICBldmVudDogQ3JlYXRlRG9uYXRpb25hdHRlbXB0Qm9keUV2ZW50O1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL2RvbmF0aW9uLnB5LyNsaW5lcy04XG4gKi9cblxuZXhwb3J0IGVudW0gQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2VFdmVudCB7XG4gICAgQ0xPU0UgPSAnQ0xPU0UnLFxuICAgIFJFQ0FMTCA9ICdSRUNBTEwnLFxuICAgIFNUQVJUID0gJ1NUQVJUJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZSB7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBldmVudDogQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2VFdmVudDtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEV4dGVybmFsIEFwcHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZXh0ZXJuYWxfYXBwcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRXh0ZXJuYWxBcHBzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIEF1dGhvcml6ZSBhIGdpdmVuIGV4dGVybmFsIGFwcCB0b2tlblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENhbiBiZSBjYWxsZWQgYnkgdGhlIEFQSSBHYXRld2F5IGluIG9yZGVyIHRvIGF1dGhvcml6ZSBldmVyeSByZXF1ZXN0IHVzaW5nIHByb3ZpZGVkIHRva2VuLiBJdCBtdXN0IGJlIHVzZWQgb25seSBmb3IgZXh0ZXJuYWwgYXBwIHRva2Vucywgd2hpY2ggYXJlIHVzZWQgYnkgdGhlIGV4dGVybmFsIGFwcHMgdG8gbWFrZSBjYWxscyBvbiBiZWhhbGYgb2YgYSBnaXZlbiB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyBhdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguQXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4oJy9leHRlcm5hbC9hdXRoX3Rva2Vucy9hdXRob3JpemUvJywge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRXh0ZXJuYWwgQXBwIENvbmZpZ3VyYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4oJy9leHRlcm5hbC9hdXRoX3Rva2Vucy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRXh0ZXJuYWwgQXBwIGNvbmZpZ3VyYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEV4dGVybmFsYXBwY29uZihwYXJhbXM6IFguUmVhZEV4dGVybmFsYXBwY29uZlF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+KCcvZXh0ZXJuYWwvYXBwcy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEV4dGVybmFsYXBwY29uZjIocGFyYW1zOiBYLlJlYWRFeHRlcm5hbGFwcGNvbmZRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4oJy9leHRlcm5hbC9hcHBzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBGb2N1cyBSZWNvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZvY3VzX3JlY29yZHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZvY3VzUmVjb3Jkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgRm9jdXMgUmVjb3JkXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZvY3VzcmVjb3JkKGJvZHk6IFguQ3JlYXRlRm9jdXNyZWNvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZvY3VzcmVjb3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZvY3VzcmVjb3JkUmVzcG9uc2U+KCcvZm9jdXNfcmVjb3Jkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRm9jdXMgUmVjb3JkIFN1bW1hcnlcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZvY3VzUmVjb3JkU3VtbWFyeSgpOiBEYXRhU3RhdGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4oJy9mb2N1c19yZWNvcmRzL3N1bW1hcnkvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRm9jdXNSZWNvcmRTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+KCcvZm9jdXNfcmVjb3Jkcy9zdW1tYXJ5LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRnJhZ21lbnQgSGFzaHRhZ3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZnJhZ21lbnRfaGFzaHRhZ3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZyYWdtZW50SGFzaHRhZ3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBIYXNodGFnc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgSGFzaHRhZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL2hhc2h0YWdzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy9oYXNodGFncy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgUHVibGlzaGVkIEhhc2h0YWdzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgSGFzaHRhZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL2hhc2h0YWdzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL2hhc2h0YWdzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZyYWdtZW50IFdvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZyYWdtZW50X3dvcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBGcmFnbWVudFdvcmRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgV29yZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFdvcmRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvd29yZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBXb3Jkc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFdvcmRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBGcmFnbWVudHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZnJhZ21lbnRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBGcmFnbWVudHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBSZW1vdGUgRnJhZ21lbnRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBSZW1vdGUgRnJhZ21lbnRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEZyYWdtZW50czIocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgUmVtb3RlIEZyYWdtZW50c1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRnJhZ21lbnQoKTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZyYWdtZW50UmVzcG9uc2U+KCcvZnJhZ21lbnRzLycsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlbGV0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBEZWxldGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkRlbGV0ZUZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE1lcmdlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIE1lcmdlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBtZXJnZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5NZXJnZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLk1lcmdlRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9tZXJnZS9gLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQdWJsaXNoIFJlbW90ZSBGcmFnbWVudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFB1Ymxpc2ggUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIHB1Ymxpc2hGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUHVibGlzaEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguUHVibGlzaEZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vcHVibGlzaC9gLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIFJlbW90ZSBGcmFnbWVudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIHJlYWRGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRGcmFnbWVudDIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRnJhZ21lbnQgRGlmZlxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgRnJhZ21lbnQgRGlmZlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRnJhZ21lbnREaWZmKGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L2RpZmYvYCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRnJhZ21lbnREaWZmMihmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vZGlmZi9gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEZyYWdtZW50IFNhbXBsZVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgRnJhZ21lbnQgU2FtcGxlXG4gICAgICovXG4gICAgcHVibGljIHJlYWRGcmFnbWVudFNhbXBsZShmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vc2FtcGxlL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRGcmFnbWVudFNhbXBsZTIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9zYW1wbGUvYCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSwgYm9keTogWC5VcGRhdGVGcmFnbWVudEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEdlb21ldHJpZXMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZ2VvbWV0cmllcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgR2VvbWV0cmllc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IEdlb21ldHJpZXNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IEdlb21ldHJpZXMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkR2VvbWV0cmllcyhwYXJhbXM6IFguQnVsa1JlYWRHZW9tZXRyaWVzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEdlb21ldHJpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEdlb21ldHJpZXNSZXNwb25zZUVudGl0eVtdPignL2dyaWQvZ2VvbWV0cmllcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRHZW9tZXRyaWVzMihwYXJhbXM6IFguQnVsa1JlYWRHZW9tZXRyaWVzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9ncmlkL2dlb21ldHJpZXMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFVwZGF0ZSBHZW9tZXRyaWVzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIGluIGEgQnVsayBsaXN0IG9mIEdlb21ldHJpZXMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtVcGRhdGVHZW9tZXRyaWVzKGJvZHk6IFguQnVsa1VwZGF0ZUdlb21ldHJpZXNCb2R5KTogT2JzZXJ2YWJsZTxYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguQnVsa1VwZGF0ZUdlb21ldHJpZXNSZXNwb25zZT4oJy9ncmlkL2dlb21ldHJpZXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEdlb21ldHJ5IGJ5IENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIGEgR2VvbWV0cnkgZW50aXR5IGdpdmVuIHRoZSBpZCBvZiBDYXJkIHdoaWNoIGlzIHRoZSBwYXJlbnQgb2YgdGhlIEdlb21ldHJ5IGVudGl0eS5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEdlb21ldHJ5QnlDYXJkKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEdlb21ldHJ5QnlDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPihgL2dyaWQvZ2VvbWV0cmllcy9ieV9jYXJkLyR7Y2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEdlb21ldHJ5QnlDYXJkMihjYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEdlb21ldHJ5QnlDYXJkUmVzcG9uc2U+KGAvZ3JpZC9nZW9tZXRyaWVzL2J5X2NhcmQvJHtjYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBHcmFwaFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbmRlciBhbmQgcmVhZCBHcmFwaCBtYWRlIG91dCBvZiBhbGwgQ2FyZHMgYW5kIExpbmtzIGJlbG9uZ2luZyB0byBhIGdpdmVuIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRHcmFwaChwYXJhbXM6IFguUmVhZEdyYXBoUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkR3JhcGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEdyYXBoUmVzcG9uc2U+KCcvZ3JpZC9ncmFwaHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRHcmFwaDIocGFyYW1zOiBYLlJlYWRHcmFwaFF1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRHcmFwaFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkR3JhcGhSZXNwb25zZT4oJy9ncmlkL2dyYXBocy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogR29zc2lwIENvbW1hbmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2dvc3NpcC5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgR29zc2lwRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBhbGwgc3VwcG9ydGVkIHNwb2tlbiBsYW5ndWFnZXNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRTcGVlY2hMYW5ndWFnZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRTcGVlY2hMYW5ndWFnZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFNwZWVjaExhbmd1YWdlc1Jlc3BvbnNlRW50aXR5W10+KCcvZ29zc2lwL3NwZWVjaC9sYW5ndWFnZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFNwZWVjaExhbmd1YWdlczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRTcGVlY2hMYW5ndWFnZXNSZXNwb25zZUVudGl0eVtdPignL2dvc3NpcC9zcGVlY2gvbGFuZ3VhZ2VzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBhbGwgc3VwcG9ydGVkIHZvaWNlIGxhbmd1YWdlc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFRleHRMYW5ndWFnZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRUZXh0TGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRUZXh0TGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4oJy9nb3NzaXAvdGV4dC9sYW5ndWFnZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFRleHRMYW5ndWFnZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRleHRMYW5ndWFnZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFRleHRMYW5ndWFnZXNSZXNwb25zZUVudGl0eVtdPignL2dvc3NpcC90ZXh0L2xhbmd1YWdlcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZXRlY3Qgc3Bva2VuIGxhbmd1YWdlXG4gICAgICovXG4gICAgcHVibGljIGRldGVjdFNwZWVjaExhbmd1YWdlcyhib2R5OiBYLkRldGVjdFNwZWVjaExhbmd1YWdlc0JvZHkpOiBPYnNlcnZhYmxlPFguRGV0ZWN0U3BlZWNoTGFuZ3VhZ2VzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkRldGVjdFNwZWVjaExhbmd1YWdlc1Jlc3BvbnNlPignL2dvc3NpcC9zcGVlY2gvZGV0ZWN0X2xhbmd1YWdlcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERldGVjdCB3cml0dGVuIGxhbmd1YWdlXG4gICAgICovXG4gICAgcHVibGljIGRldGVjdFRleHRMYW5ndWFnZXMoYm9keTogWC5EZXRlY3RUZXh0TGFuZ3VhZ2VzQm9keSk6IE9ic2VydmFibGU8WC5EZXRlY3RUZXh0TGFuZ3VhZ2VzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkRldGVjdFRleHRMYW5ndWFnZXNSZXNwb25zZT4oJy9nb3NzaXAvdGV4dC9kZXRlY3RfbGFuZ3VhZ2VzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBIYXNodGFncyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9oYXNodGFncy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSGFzaHRhZ3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBIYXNodGFnc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGxpc3QgYSBzZXJpZXMgb2YgSGFzaHRhZyBpbnN0YW5jZXMuIEl0IGFjY2VwdHMgdmFyaW91cyBxdWVyeSBwYXJhbWV0ZXJzIHN1Y2ggYXM6IC0gYGxpbWl0YCAtIGBvZmZzZXRgIC0gYGZpcnN0X2NoYXJhY3RlcmBcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2hhc2h0YWdzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9oYXNodGFncy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0aW5nIGEgc2luZ2xlIEhhc2h0YWdcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBjcmVhdGUgYSBzaW5nbGUgSGFzaHRhZyBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlSGFzaHRhZyhib2R5OiBYLkNyZWF0ZUhhc2h0YWdCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlSGFzaHRhZ1Jlc3BvbnNlPignL2hhc2h0YWdzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZpbmcgYSBzaW5nbGUgSGFzaHRhZ1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGRldGFjaCBhIHNpbmdsZSBIYXNodGFnIGluc3RhbmNlIGZyb20gYSBsaXN0IGNhcmRzIGdpdmVuIGJ5IGBjYXJkX2lkc2AuXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIHBhcmFtczogWC5EZWxldGVIYXNodGFnUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkRlbGV0ZUhhc2h0YWdSZXNwb25zZT4oYC9oYXNodGFncy8ke2hhc2h0YWdJZH1gLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBIYXNodGFncyBUT0NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBsaXN0IEhhc2h0YWdzIFRhYmxlIG9mIENvbnRlbnRzIG1hZGUgb3V0IG9mIEhhc2h0YWdzLiBOb3RlOiBDdXJyZW50bHkgdGhpcyBlbmRwb2ludCByZXR1cm5zIG9ubHkgYSBmbGF0IGxpc3Qgb2YgaGFzaHRhZ3Mgd2l0aCB0aGUgY291bnQgb2YgQ2FyZHMgd2l0aCB3aGljaCB0aGV5J3JlIGF0dGFjaGVkIHRvLiBJbiB0aGUgZnV0dXJlIHRob3VnaCBvbmUgY291bGQgcHJvcG9zZSBhIG1lY2hhbmlzbSB3aGljaCBjb3VsZCBjYWxjdWxhdGUgaGllcmFyY2h5IGJldHdlZW4gdGhvc2UgaGFzaHRhZ3MgKHBhcmVudCAtIGNoaWxkIHJlbGF0aW9uc2hpcHMpIGFuZCBvcmRlcmluZyBiYXNlZCBvbiB0aGUga25vd2xlZGdlIGdyaWQgdG9wb2xvZ3kuIEl0IGFjY2VwdHMgdmFyaW91cyBxdWVyeSBwYXJhbWV0ZXJzIHN1Y2ggYXM6IC0gYGxpbWl0YCAtIGBvZmZzZXRgXG4gICAgICovXG4gICAgcHVibGljIHJlYWRIYXNodGFnc1RvYyhwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+KCcvaGFzaHRhZ3MvdG9jLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkSGFzaHRhZ3NUb2MyKHBhcmFtczogWC5SZWFkSGFzaHRhZ3NUb2NRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+KCcvaGFzaHRhZ3MvdG9jLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRpbmcgYSBzaW5nbGUgSGFzaHRhZ1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIHVwZGF0ZSBhIHNpbmdsZSBIYXNodGFnIGluc3RhbmNlIHdpdGggYSBsaXN0IG9mIGBjYXJkX2lkc2AgdG8gd2hpY2ggaXQgc2hvdWxkIGdldCBhdHRhY2hlZCB0by5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlSGFzaHRhZyhoYXNodGFnSWQ6IGFueSwgYm9keTogWC5VcGRhdGVIYXNodGFnQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVIYXNodGFnUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlSGFzaHRhZ1Jlc3BvbnNlPihgL2hhc2h0YWdzLyR7aGFzaHRhZ0lkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBJbnZvaWNlIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ludm9pY2VzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBJbnZvaWNlc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IGFsbCBJbnZvaWNlcyBiZWxvbmdpbmcgdG8gYSBnaXZlbiB1c2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gbGlzdCBhbGwgb2YgdGhlIEludm9pY2VzIHdoaWNoIHdlcmUgZ2VuZXJhdGVkIGZvciBoaXMgRG9uYXRpb25zIG9yIFN1YnNjcmlwdGlvbiBwYXltZW50cy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRJbnZvaWNlcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+KCcvcGF5bWVudHMvaW52b2ljZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEludm9pY2VzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUVudGl0eVtdPignL3BheW1lbnRzL2ludm9pY2VzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhbGN1bGF0ZSBkZWJ0IGZvciBhIGdpdmVuIHVzZXJcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDYWxjdWxhdGUgZGVidCBmb3IgYSBnaXZlbiB1c2VyIGJ5IHNlYXJjaGluZyBmb3IgdGhlIGxhdGVzdCB1bnBhaWQgaW52b2ljZS4gSXQgcmV0dXJucyBwYXltZW50IHRva2VuIHdoaWNoIGNhbiBiZSB1c2VkIGluIHRoZSBQQUlEX1dJVEhfREVGQVVMVF9QQVlNRU5UX0NBUkQgY29tbWFuZFxuICAgICAqL1xuICAgIHB1YmxpYyBjYWxjdWxhdGVEZWJ0KCk6IERhdGFTdGF0ZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQ2FsY3VsYXRlRGVidFJlc3BvbnNlPignL3BheW1lbnRzL2ludm9pY2VzL2RlYnQvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBjYWxjdWxhdGVEZWJ0MigpOiBPYnNlcnZhYmxlPFguQ2FsY3VsYXRlRGVidFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5DYWxjdWxhdGVEZWJ0UmVzcG9uc2U+KCcvcGF5bWVudHMvaW52b2ljZXMvZGVidC8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEludm9pY2UgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9pbnZvaWNlLnB5LyNsaW5lcy01M1xuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHkge1xuICAgIGFtb3VudDogc3RyaW5nO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgY3VycmVuY3k/OiBzdHJpbmc7XG4gICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICBpZD86IG51bWJlcjtcbiAgICBpc19leHRlbnNpb24/OiBib29sZWFuO1xuICAgIHBhaWRfdGlsbF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBwcm9kdWN0OiB7XG4gICAgICAgIGN1cnJlbmN5PzogQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgcHJvZHVjdF90eXBlOiBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VQcm9kdWN0VHlwZTtcbiAgICB9O1xuICAgIHN1cnBsdXNfYW1vdW50Pzogc3RyaW5nO1xuICAgIHN1cnBsdXNfY3VycmVuY3k/OiBzdHJpbmc7XG4gICAgdmFsaWRfdGlsbF90aW1lc3RhbXA6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2Uge1xuICAgIGludm9pY2VzOiBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9pbnZvaWNlLnB5LyNsaW5lcy01MVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2FsY3VsYXRlRGVidFJlc3BvbnNlIHtcbiAgICBhdF9fY29tbWFuZHM6IE9iamVjdDtcbiAgICBjdXJyZW5jeTogc3RyaW5nO1xuICAgIGRpc3BsYXlfb3dlczogc3RyaW5nO1xuICAgIG93ZXM6IG51bWJlcjtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIExpbmtzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2xpbmtzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBMaW5rc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgTGlua1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbW92ZSBhIExpbmsgYmV0d2VlbiB0d28gY2FyZHMuXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZUxpbmsoZnJvbUNhcmRJZDogYW55LCB0b0NhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUxpbmtSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVMaW5rUmVzcG9uc2U+KGAvZ3JpZC9saW5rcy8ke2Zyb21DYXJkSWR9LyR7dG9DYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIG9yIENyZWF0ZSBMaW5rXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBvciBDcmVhdGUgYSBMaW5rIGJldHdlZW4gdHdvIGNhcmRzLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkT3JDcmVhdGVMaW5rKGJvZHk6IFguUmVhZE9yQ3JlYXRlTGlua0JvZHkpOiBPYnNlcnZhYmxlPFguUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5SZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2U+KCcvZ3JpZC9saW5rcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogTGlua3MgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy81ZjIxNWZhYmJhN2ZhMzkyNTE1MWMwOThmYWQwMDUxMTYyNDUyODIxLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBEZWxldGVMaW5rUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy81ZjIxNWZhYmJhN2ZhMzkyNTE1MWMwOThmYWQwMDUxMTYyNDUyODIxL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL2dyaWQvdmlld3MucHkvI2xpbmVzLTQ4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBSZWFkT3JDcmVhdGVMaW5rQm9keSB7XG4gICAgZnJvbV9jYXJkX2lkOiBudW1iZXI7XG4gICAgdG9fY2FyZF9pZDogbnVtYmVyO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjLzVmMjE1ZmFiYmE3ZmEzOTI1MTUxYzA5OGZhZDAwNTExNjI0NTI4MjEvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvZ3JpZC9zZXJpYWxpemVycy5weS8jbGluZXMtOFxuICovXG5cbmV4cG9ydCBlbnVtIFJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZUtpbmQge1xuICAgIENBUkQgPSAnQ0FSRCcsXG4gICAgRlJBR01FTlQgPSAnRlJBR01FTlQnLFxuICAgIEhBU0hUQUcgPSAnSEFTSFRBRycsXG4gICAgUEFUSCA9ICdQQVRIJyxcbiAgICBURVJNID0gJ1RFUk0nLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZSB7XG4gICAgYXV0aG9yX2lkPzogYW55O1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZnJvbV9jYXJkX2lkPzogYW55O1xuICAgIGlkPzogbnVtYmVyO1xuICAgIGtpbmQ6IFJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZUtpbmQ7XG4gICAgcmVmZXJlbmNlX2lkOiBudW1iZXI7XG4gICAgdG9fY2FyZF9pZD86IGFueTtcbiAgICB2YWx1ZTogbnVtYmVyO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogTWVkaWFJdGVtcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9tZWRpYWl0ZW1zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBNZWRpYWl0ZW1zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgTWVkaWFJdGVtc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgTWVkaWFJdGVtc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZE1lZGlhaXRlbXMocGFyYW1zOiBYLkJ1bGtSZWFkTWVkaWFpdGVtc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4oJy9tZWRpYWl0ZW1zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZE1lZGlhaXRlbXMyKHBhcmFtczogWC5CdWxrUmVhZE1lZGlhaXRlbXNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPignL21lZGlhaXRlbXMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgTWVkaWFJdGVtXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVtb3ZlIE1lZGlhSXRlbSBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnksIHBhcmFtczogWC5EZWxldGVNZWRpYWl0ZW1RdWVyeSk6IE9ic2VydmFibGU8WC5EZWxldGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVNZWRpYWl0ZW1SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9YCwgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgTWVkaWFJdGVtXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBNZWRpYUl0ZW1cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55KTogRGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy8ke21lZGlhaXRlbUlkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbTIobWVkaWFpdGVtSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRNZWRpYWl0ZW1SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBCeSBQcm9jZXNzIElkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBNZWRpYUl0ZW0gYnkgUHJvY2VzcyBJZFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWQoKTogRGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPignL21lZGlhaXRlbXMvYnlfcHJvY2Vzcy8oP1A8cHJvY2Vzc19pZD5bXFx3K1xcPV0rKScsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkMigpOiBPYnNlcnZhYmxlPFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPignL21lZGlhaXRlbXMvYnlfcHJvY2Vzcy8oP1A8cHJvY2Vzc19pZD5bXFx3K1xcPV0rKScsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgb3IgQ3JlYXRlIE1lZGlhSXRlbVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgb3IgQ3JlYXRlIE1lZGlhSXRlbSBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE9yQ3JlYXRlTWVkaWFpdGVtKGJvZHk6IFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtQm9keSk6IE9ic2VydmFibGU8WC5SZWFkT3JDcmVhdGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtUmVzcG9uc2U+KCcvbWVkaWFpdGVtcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBNZWRpYUl0ZW1cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgTWVkaWFJdGVtIGluc3RhbmNlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVNZWRpYWl0ZW0obWVkaWFpdGVtSWQ6IGFueSwgYm9keTogWC5VcGRhdGVNZWRpYWl0ZW1Cb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZU1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZU1lZGlhaXRlbVJlc3BvbnNlPihgL21lZGlhaXRlbXMvJHttZWRpYWl0ZW1JZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBNZWRpYUl0ZW0gUmVwcmVzZW50YXRpb25cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgZ2l2ZW4gTWVkaWFJdGVtIHdpdGggb25seSB0aGUgZmllbGRzIHdoaWNoIGFyZSBkZWNpZGVkIGV4dGVybmFsbHkgKHVzaW5nIGV4dGVybmFsIHNlcnZpY2VzKS4gRmllbGRzIGxpa2U6IC0gYHdlYl9yZXByZXNlbnRhdGlvbnNgIC0gYHRodW1ibmFpbF91cmlgIC0gYG1ldGFgIC0gYHRleHRgIEFsbCBvZiB0aG9zZSBmaWVsZHMgYXJlIGNvbXB1dGVkIGluIHNtYXJ0ZXIgd2F5IGluIG9yZGVyIHRvIG1ha2UgdGhlIE1lZGlhSXRlbSB3YXkgYmV0dGVyIGluIGEgc2VtYW50aWMgc2Vuc2UuIFRob3NlIGZpZWxkcyBhcmUgcGVyY2VpdmVkIGFzIHRoZSBgcmVwcmVzZW50YXRpb25gIG9mIGEgZ2l2ZW4gTWVkaWFJdGVtIHNpbmNlIHRoZXkgY29udGFpbnMgaW5mb3JtYXRpb24gYWJvdXQgaG93IHRvIGRpc3BsYXkgYSBnaXZlbiBNZWRpYUl0ZW0sIGhvdyB0byB1bmRlcnN0YW5kIGl0IGV0Yy4gSXQgZ29lcyBiZXlvbmQgdGhlIHNpbXBsZSBhYnN0cmFjdCBkYXRhIG9yaWVudGVkIHJlcHJlc2VudGF0aW9uICh1cmksIGV4dGVuc2lvbiBldGMuKS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb24obWVkaWFpdGVtSWQ6IGFueSwgYm9keTogWC5VcGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvblJlc3BvbnNlPihgL21lZGlhaXRlbXMvJHttZWRpYWl0ZW1JZH0vcmVwcmVzZW50YXRpb24vYCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIE5vdGlmaWNhdGlvbiBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9ub3RpZmljYXRpb25zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBOb3RpZmljYXRpb25zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIEFja25vd2xlZGdlIE5vdGlmaWNhdGlvblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEFja25vd2xlZGdlIE5vdGlmaWNhdGlvblxuICAgICAqL1xuICAgIHB1YmxpYyBhY2tub3dsZWRnZU5vdGlmaWNhdGlvbihub3RpZmljYXRpb25JZDogYW55KTogT2JzZXJ2YWJsZTxYLkFja25vd2xlZGdlTm90aWZpY2F0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguQWNrbm93bGVkZ2VOb3RpZmljYXRpb25SZXNwb25zZT4oYC9ub3RpZmljYXRpb25zLyR7bm90aWZpY2F0aW9uSWR9L2Fja25vd2xlZGdlL2AsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgTm90aWZpY2F0aW9uc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgTm90aWZpY2F0aW9uc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZE5vdGlmaWNhdGlvbnMocGFyYW1zOiBYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4oJy9ub3RpZmljYXRpb25zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZE5vdGlmaWNhdGlvbnMyKHBhcmFtczogWC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdPignL25vdGlmaWNhdGlvbnMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIE5vdGlmaWNhdGlvbiBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZnJhZ21lbnQtc2VydmljZS9zcmMvMzcwOWI1MmU2ZDdjNzM5OTE1NDU4MmU4MDU1YzBlNzYxMzlhNGMwMC8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQWNrbm93bGVkZ2VOb3RpZmljYXRpb25SZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZnJhZ21lbnQtc2VydmljZS9zcmMvMzcwOWI1MmU2ZDdjNzM5OTE1NDU4MmU4MDU1YzBlNzYxMzlhNGMwMC9jb3NwaGVyZV9mcmFnbWVudF9zZXJ2aWNlL25vdGlmaWNhdGlvbi92aWV3cy5weS8jbGluZXMtNzdcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkTm90aWZpY2F0aW9uc1F1ZXJ5IHtcbiAgICBhY2tub3dsZWRnZWQ/OiBib29sZWFuO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wX19ndD86IG51bWJlcjtcbiAgICBsaW1pdD86IG51bWJlcjtcbiAgICBvZmZzZXQ/OiBudW1iZXI7XG4gICAgdXBkYXRlZF90aW1lc3RhbXBfX2d0PzogbnVtYmVyO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZnJhZ21lbnQtc2VydmljZS9zcmMvMzcwOWI1MmU2ZDdjNzM5OTE1NDU4MmU4MDU1YzBlNzYxMzlhNGMwMC9jb3NwaGVyZV9mcmFnbWVudF9zZXJ2aWNlL25vdGlmaWNhdGlvbi9zZXJpYWxpemVycy5weS8jbGluZXMtNDZcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUtpbmQge1xuICAgIEZSQUdNRU5UX1VQREFURSA9ICdGUkFHTUVOVF9VUERBVEUnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBhY2tub3dsZWRnZWQ6IGJvb2xlYW47XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBpZD86IG51bWJlcjtcbiAgICBraW5kOiBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUtpbmQ7XG4gICAgcGF5bG9hZDogT2JqZWN0O1xuICAgIHVwZGF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2Uge1xuICAgIG5vdGlmaWNhdGlvbnM6IEJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W107XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBOb3VucyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9ub3Vucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTm91bnNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQnVsayBSZWFkIE5vdW4gUHJvamVjdCBJY29uc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEljb25zKHBhcmFtczogWC5CdWxrUmVhZEljb25zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEljb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRJY29uc1Jlc3BvbnNlRW50aXR5W10+KCcvbm91bnMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkSWNvbnMyKHBhcmFtczogWC5CdWxrUmVhZEljb25zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRJY29uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkSWNvbnNSZXNwb25zZUVudGl0eVtdPignL25vdW5zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBQYXRocyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9wYXRocy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUGF0aHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogRGVsZXRlIFBhdGhzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5kcG9pbnQgZm9yIERlbGV0aW5nIG11bHRpcGxlIFBhdGhzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrRGVsZXRlUGF0aHMocGFyYW1zOiBYLkJ1bGtEZWxldGVQYXRoc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtEZWxldGVQYXRoc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkJ1bGtEZWxldGVQYXRoc1Jlc3BvbnNlPignL3BhdGhzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFBhdGhzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBhbGwgdXNlcidzIFBhdGhzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUGF0aHMocGFyYW1zOiBYLkJ1bGtSZWFkUGF0aHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXRocy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRQYXRoczIocGFyYW1zOiBYLkJ1bGtSZWFkUGF0aHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+KCcvcGF0aHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgUGF0aFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuZHBvaW50IGZvciBDcmVhdGluZyBQYXRoLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVQYXRoKGJvZHk6IFguQ3JlYXRlUGF0aEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVQYXRoUmVzcG9uc2U+KCcvcGF0aHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIFBhdGhcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIHNpbmdsZSBQYXRoXG4gICAgICovXG4gICAgcHVibGljIHJlYWRQYXRoKHBhdGhJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZFBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZFBhdGhSZXNwb25zZT4oYC9wYXRocy8ke3BhdGhJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRQYXRoMihwYXRoSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkUGF0aFJlc3BvbnNlPihgL3BhdGhzLyR7cGF0aElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBQYXRoXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5kcG9pbnQgZm9yIFVwZGF0aW5nIFBhdGguXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZVBhdGgocGF0aElkOiBhbnksIGJvZHk6IFguVXBkYXRlUGF0aEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZVBhdGhSZXNwb25zZT4oYC9wYXRocy8ke3BhdGhJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUGF5bWVudCBDYXJkcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9wYXltZW50X2NhcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBQYXltZW50Q2FyZHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTWFyayBhIGdpdmVuIFBheW1lbnQgQ2FyZCBhcyBhIGRlZmF1bHQgb25lXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gbWFyayBhIHNwZWNpZmljIFBheW1lbnQgQ2FyZCBhcyBhIGRlZmF1bHQgb25lLCBtZWFuaW5nIHRoYXQgaXQgd2lsbCBiZSB1c2VkIGZvciBhbGwgdXBjb21pbmcgcGF5bWVudHMuIE1hcmtpbmcgUGF5bWVudCBDYXJkIGFzIGEgZGVmYXVsdCBvbmUgYXV0b21hdGljYWxseSBsZWFkcyB0byB0aGUgdW5tYXJraW5nIG9mIGFueSBQYXltZW50IENhcmQgd2hpY2ggd2FzIGRlZmF1bHQgb25lIGJlZm9yZSB0aGUgaW52b2NhdGlvbiBvZiB0aGUgY29tbWFuZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgYXNEZWZhdWx0TWFya1BheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5Bc0RlZmF1bHRNYXJrUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5Bc0RlZmF1bHRNYXJrUGF5bWVudGNhcmRSZXNwb25zZT4oYC9wYXltZW50cy9wYXltZW50X2NhcmRzLyR7cGF5bWVudENhcmRJZH0vbWFya19hc19kZWZhdWx0L2AsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgYWxsIFBheW1lbnQgQ2FyZHMgYmVsb25naW5nIHRvIGEgZ2l2ZW4gdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIGxpc3QgYWxsIG9mIHRoZSBQYXltZW50IENhcmRzIHdoaWNoIHdlcmUgYWRkZWQgYnkgaGltIC8gaGVyLiBBbW9uZyBhbGwgcmV0dXJuZWQgUGF5bWVudCBDYXJkcyB0aGVyZSBtdXN0IGJlIG9uZSBhbmQgb25seSBvbmUgd2hpY2ggaXMgbWFya2VkIGFzICoqZGVmYXVsdCoqLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFBheW1lbnRjYXJkcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRQYXltZW50Y2FyZHMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIFBheW1lbnQgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIGFkZCBuZXcgUGF5bWVudCBDYXJkLCB3aGljaCBjb3VsZCBiZSBuZWVkZWQgaW4gY2FzZXMgd2hlbiB0aGUgVXNlciB3b3VsZCBsaWtlIHRvIHJlcGxhY2UgZXhpc3RpbmcgUGF5bWVudCBDYXJkIGJlY2F1c2U6IC0gaXQgZXhwaXJlZCAtIGlzIGVtcHR5IC0gdGhlIFVzZXIgcHJlZmVycyBhbm90aGVyIG9uZSB0byBiZSB1c2VkIGZyb20gbm93IG9uLiBVc2luZyB0aGUgb3B0aW9uYWwgYG1hcmtfYXNfZGVmYXVsdGAgZmllbGQgb25lIGNhbiBtYXJrIGp1c3QgY3JlYXRlZCBQYXltZW50IENhcmQgYXMgdGhlIGRlZmF1bHQgb25lLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVQYXltZW50Y2FyZChib2R5OiBYLkNyZWF0ZVBheW1lbnRjYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlPignL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgYSBnaXZlbiBQYXltZW50IENhcmQgYmVsb25naW5nIHRvIGEgZ2l2ZW4gdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIHJlbW92ZSBhIHNwZWNpZmljIFBheW1lbnQgQ2FyZCB3aGljaCB3ZXJlIGFkZGVkIGJ5IGhpbSAvIGhlci4gUGF5bWVudCBDYXJkIGNhbiBiZSByZW1vdmVkIG9ubHkgaWYgaXQncyBub3QgYSBkZWZhdWx0IG9uZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlUGF5bWVudGNhcmQocGF5bWVudENhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZVBheW1lbnRjYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlUGF5bWVudGNhcmRSZXNwb25zZT4oYC9wYXltZW50cy9wYXltZW50X2NhcmRzLyR7cGF5bWVudENhcmRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBheSB1c2luZyB0aGUgZGVmYXVsdCBQYXltZW50IENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVc2VyIGlzIGFsbG93ZWQgb25seSB0byBwZXJmb3JtIHBheW1lbnRzIGFnYWluc3QgaGVyIGRlZmF1bHQgUGF5bWVudCBDYXJkLiBJbiBvdGhlciB3b3JkcyBvbiBvcmRlciB0byB1c2UgYSBnaXZlbiBQYXltZW50IENhcmQgb25lIGhhcyB0byBtYXJrIGlzIGFzIGRlZmF1bHQuIEFsc28gb25lIGlzIG5vdCBhbGxvd2VkIHRvIHBlcmZvcm0gc3VjaCBwYXltZW50cyBmcmVlbHkgYW5kIHRoZXJlZm9yZSB3ZSBleHBlY3QgdG8gZ2V0IGEgYHBheW1lbnRfdG9rZW5gIGluc2lkZSB3aGljaCBhbm90aGVyIHBpZWNlIG9mIG91ciBzeXN0ZW0gZW5jb2RlZCBhbGxvd2VkIHN1bSB0byBiZSBwYWlkLlxuICAgICAqL1xuICAgIHB1YmxpYyBwYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkKGJvZHk6IFguUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5QYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2U+KCcvcGF5bWVudHMvcGF5bWVudF9jYXJkcy9wYXlfd2l0aF9kZWZhdWx0LycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGEgUGF5bWVudCBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gYWRkIG5ldyBQYXltZW50IENhcmQsIHdoaWNoIGNvdWxkIGJlIG5lZWRlZCBpbiBjYXNlcyB3aGVuIHRoZSBVc2VyIHdvdWxkIGxpa2UgdG8gcmVwbGFjZSBleGlzdGluZyBQYXltZW50IENhcmQgYmVjYXVzZTogLSBpdCBleHBpcmVkIC0gaXMgZW1wdHkgLSB0aGUgVXNlciBwcmVmZXJzIGFub3RoZXIgb25lIHRvIGJlIHVzZWQgZnJvbSBub3cgb25cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVuZGVyUGF5bWVudENhcmRXaWRnZXQoKTogRGF0YVN0YXRlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzL3dpZGdldC8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlbmRlclBheW1lbnRDYXJkV2lkZ2V0MigpOiBPYnNlcnZhYmxlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzL3dpZGdldC8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFBheW1lbnQgQ2FyZHMgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQXNEZWZhdWx0TWFya1BheW1lbnRjYXJkUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9wYXltZW50X2NhcmQucHkvI2xpbmVzLTc1XG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VTdGF0dXMge1xuICAgIENBTkNFTEVEID0gJ0NBTkNFTEVEJyxcbiAgICBDT01QTEVURUQgPSAnQ09NUExFVEVEJyxcbiAgICBORVcgPSAnTkVXJyxcbiAgICBQRU5ESU5HID0gJ1BFTkRJTkcnLFxuICAgIFJFSkVDVEVEID0gJ1JFSkVDVEVEJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBleHBpcmF0aW9uX21vbnRoPzogbnVtYmVyO1xuICAgIGV4cGlyYXRpb25feWVhcj86IG51bWJlcjtcbiAgICBleHBpcmVkOiBib29sZWFuO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIGlzX2RlZmF1bHQ/OiBib29sZWFuO1xuICAgIGlzX2Z1bGx5X2RlZmluZWQ6IGJvb2xlYW47XG4gICAgbWFza2VkX251bWJlcjogc3RyaW5nO1xuICAgIHBheW1lbnRzOiB7XG4gICAgICAgIGFtb3VudDogc3RyaW5nO1xuICAgICAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgICAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0OiB7XG4gICAgICAgICAgICBjdXJyZW5jeT86IEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICAgICAgcHJvZHVjdF90eXBlOiBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgICAgIH07XG4gICAgICAgIHN0YXR1cz86IEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VTdGF0dXM7XG4gICAgICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG4gICAgfVtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2Uge1xuICAgIHBheW1lbnRfY2FyZHM6IEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9wYXltZW50X2NhcmQucHkvI2xpbmVzLTUyXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVQYXltZW50Y2FyZEJvZHkge1xuICAgIGV4cGlyYXRpb25fbW9udGg6IG51bWJlcjtcbiAgICBleHBpcmF0aW9uX3llYXI6IG51bWJlcjtcbiAgICBtYXJrX2FzX2RlZmF1bHQ/OiBib29sZWFuO1xuICAgIG1hc2tlZF9udW1iZXI6IHN0cmluZztcbiAgICB0b2tlbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnRfY2FyZC5weS8jbGluZXMtOVxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlU3RhdHVzIHtcbiAgICBDQU5DRUxFRCA9ICdDQU5DRUxFRCcsXG4gICAgQ09NUExFVEVEID0gJ0NPTVBMRVRFRCcsXG4gICAgTkVXID0gJ05FVycsXG4gICAgUEVORElORyA9ICdQRU5ESU5HJyxcbiAgICBSRUpFQ1RFRCA9ICdSRUpFQ1RFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZSB7XG4gICAgZXhwaXJhdGlvbl9tb250aD86IG51bWJlcjtcbiAgICBleHBpcmF0aW9uX3llYXI/OiBudW1iZXI7XG4gICAgZXhwaXJlZDogYm9vbGVhbjtcbiAgICBpZD86IG51bWJlcjtcbiAgICBpc19kZWZhdWx0PzogYm9vbGVhbjtcbiAgICBpc19mdWxseV9kZWZpbmVkOiBib29sZWFuO1xuICAgIG1hc2tlZF9udW1iZXI6IHN0cmluZztcbiAgICBwYXltZW50czoge1xuICAgICAgICBhbW91bnQ6IHN0cmluZztcbiAgICAgICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICAgICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICAgICAgcHJvZHVjdDoge1xuICAgICAgICAgICAgY3VycmVuY3k/OiBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgICAgIHByb2R1Y3RfdHlwZTogQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgICAgICB9O1xuICAgICAgICBzdGF0dXM/OiBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlU3RhdHVzO1xuICAgICAgICBzdGF0dXNfbGVkZ2VyPzogT2JqZWN0O1xuICAgIH1bXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRGVsZXRlUGF5bWVudGNhcmRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL3BheW1lbnRfY2FyZC5weS8jbGluZXMtMjA0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkQm9keSB7XG4gICAgcGF5bWVudF90b2tlbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnQucHkvI2xpbmVzLTlcbiAqL1xuXG5leHBvcnQgZW51bSBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBlbnVtIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVN0YXR1cyB7XG4gICAgQ0FOQ0VMRUQgPSAnQ0FOQ0VMRUQnLFxuICAgIENPTVBMRVRFRCA9ICdDT01QTEVURUQnLFxuICAgIE5FVyA9ICdORVcnLFxuICAgIFBFTkRJTkcgPSAnUEVORElORycsXG4gICAgUkVKRUNURUQgPSAnUkVKRUNURUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZSB7XG4gICAgYW1vdW50OiBzdHJpbmc7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgY3VycmVuY3k/OiBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgZGlzcGxheV9wcmljZTogc3RyaW5nO1xuICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0X3R5cGU6IFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgIH07XG4gICAgc3RhdHVzPzogUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlU3RhdHVzO1xuICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvbW9kZWxzL3BheXUucHkvI2xpbmVzLTMxM1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZSB7XG4gICAgY3VycmVuY3lfY29kZTogc3RyaW5nO1xuICAgIGN1c3RvbWVyX2VtYWlsPzogc3RyaW5nO1xuICAgIGN1c3RvbWVyX2xhbmd1YWdlOiBzdHJpbmc7XG4gICAgbWVyY2hhbnRfcG9zX2lkOiBzdHJpbmc7XG4gICAgcmVjdXJyaW5nX3BheW1lbnQ6IGJvb2xlYW47XG4gICAgc2hvcF9uYW1lOiBzdHJpbmc7XG4gICAgc2lnOiBzdHJpbmc7XG4gICAgc3RvcmVfY2FyZDogYm9vbGVhbjtcbiAgICB0b3RhbF9hbW91bnQ6IHN0cmluZztcbiAgICB3aWRnZXRfbW9kZT86IHN0cmluZztcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFBheW1lbnRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3BheW1lbnRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBQYXltZW50c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgdGhlIHN0YXR1cyBvZiBhIGdpdmVuIFBheW1lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgdGhlIFBheW1lbnQgaW5zdGFuY2UgaWRlbnRpZmllZCBieSB0aGUgYHNlc3Npb25faWRgLiBUaGlzIGNvbW1hbmQgaXMgZm9yIGV4dGVybmFsIHVzZSBvbmx5IHRoZXJlZm9yZSBpdCBkb2Vzbid0IGV4cG9zZSBpbnRlcm5hbCBpZHMgb2YgdGhlIHBheW1lbnRzIGJ1dCByYXRoZXIgc2Vzc2lvbiBpZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlUGF5bWVudFN0YXR1cyhib2R5OiBYLlVwZGF0ZVBheW1lbnRTdGF0dXNCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVBheW1lbnRTdGF0dXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguVXBkYXRlUGF5bWVudFN0YXR1c1Jlc3BvbnNlPignL3BheW1lbnRzLyg/UDxzZXNzaW9uX2lkPltcXHdcXC1dKyknLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFByb2Nlc3NlcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9wcm9jZXNzZXMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFByb2Nlc3Nlc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgRGVsZXRpb24gUHJvY2Vzc1xuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVEZWxldGlvblByb2Nlc3MoYm9keTogWC5DcmVhdGVEZWxldGlvblByb2Nlc3NCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURlbGV0aW9uUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVEZWxldGlvblByb2Nlc3NSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy9kZWxldGlvbnMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgRG93bmxvYWQgUHJvY2Vzc1xuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVEb3dubG9hZFByb2Nlc3MoYm9keTogWC5DcmVhdGVEb3dubG9hZFByb2Nlc3NCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvd25sb2FkUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVEb3dubG9hZFByb2Nlc3NSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy9kb3dubG9hZHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgTWVkaWEgTG9ja1xuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVNZWRpYUxvY2soYm9keTogWC5DcmVhdGVNZWRpYUxvY2tCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZU1lZGlhTG9ja1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVNZWRpYUxvY2tSZXNwb25zZT4oJy9tZWRpYWZpbGVzL2xvY2tzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIFVwbG9hZCBQcm9jZXNzXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZVVwbG9hZFByb2Nlc3MoYm9keTogWC5DcmVhdGVVcGxvYWRQcm9jZXNzQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVVcGxvYWRQcm9jZXNzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZVVwbG9hZFByb2Nlc3NSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy91cGxvYWRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBpbnZhcmlhbnRzIGZvciBhIGdpdmVuIHVyaVxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkSW52YXJpYW50cyhwYXJhbXM6IFguUmVhZEludmFyaWFudHNRdWVyeSk6IERhdGFTdGF0ZTxYLlJlYWRJbnZhcmlhbnRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRJbnZhcmlhbnRzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9pbnZhcmlhbnRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkSW52YXJpYW50czIocGFyYW1zOiBYLlJlYWRJbnZhcmlhbnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEludmFyaWFudHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEludmFyaWFudHNSZXNwb25zZT4oJy9tZWRpYWZpbGVzL2ludmFyaWFudHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgTWVkaWEgTG9ja1xuICAgICAqL1xuICAgIHB1YmxpYyByZWFkUHJvY2Vzc1N0YXRlKHBhcmFtczogWC5SZWFkUHJvY2Vzc1N0YXRlUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRQcm9jZXNzU3RhdGVSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZFByb2Nlc3NTdGF0ZTIocGFyYW1zOiBYLlJlYWRQcm9jZXNzU3RhdGVRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRQcm9jZXNzU3RhdGVSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNpZ24gUHJvY2VzcyBkZWRpY2F0ZWQgdG8gdXBsb2FkIGFuZCBjb252ZXJzaW9uIG9mIG1lZGlhIGZpbGVcbiAgICAgKi9cbiAgICBwdWJsaWMgc2lnblByb2Nlc3MocGFyYW1zOiBYLlNpZ25Qcm9jZXNzUXVlcnkpOiBEYXRhU3RhdGU8WC5TaWduUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5TaWduUHJvY2Vzc1Jlc3BvbnNlPignL21lZGlhZmlsZXMvcHJvY2Vzc2VzL3NpZ24vJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHNpZ25Qcm9jZXNzMihwYXJhbXM6IFguU2lnblByb2Nlc3NRdWVyeSk6IE9ic2VydmFibGU8WC5TaWduUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5TaWduUHJvY2Vzc1Jlc3BvbnNlPignL21lZGlhZmlsZXMvcHJvY2Vzc2VzL3NpZ24vJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBXYXRjaCBjb252ZXJzaW9uIHN0YXR1c1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuZHBvaW50IGNhbGxlZCBieSB0aGUgZXh0ZXJuYWwgY29udmVyc2lvbiBzZXJ2aWNlLlxuICAgICAqL1xuICAgIHB1YmxpYyB3YXRjaENvbnZlcnNpb25TdGF0dXMod2FpdGVySWQ6IGFueSwgcGFyYW1zOiBYLldhdGNoQ29udmVyc2lvblN0YXR1c1F1ZXJ5KTogRGF0YVN0YXRlPFguV2F0Y2hDb252ZXJzaW9uU3RhdHVzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPihgL21lZGlhZmlsZXMvY29udmVydF9wcm9jZXNzZXMvKD9QPHByb2Nlc3NfaWQ+WzAtOWEtekEtWlxcX1xcLVxcPV0rKS8ke3dhaXRlcklkfWAsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgd2F0Y2hDb252ZXJzaW9uU3RhdHVzMih3YWl0ZXJJZDogYW55LCBwYXJhbXM6IFguV2F0Y2hDb252ZXJzaW9uU3RhdHVzUXVlcnkpOiBPYnNlcnZhYmxlPFguV2F0Y2hDb252ZXJzaW9uU3RhdHVzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPihgL21lZGlhZmlsZXMvY29udmVydF9wcm9jZXNzZXMvKD9QPHByb2Nlc3NfaWQ+WzAtOWEtekEtWlxcX1xcLVxcPV0rKS8ke3dhaXRlcklkfWAsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUXVpenplciBFbnRpdGllcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9xdWl6emVyLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBRdWl6emVyRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIEJ1aWxkIFJlYWQgUXVpeiBBdHRlbXB0c1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFF1aXphdHRlbXB0cyhxdWl6SWQ6IGFueSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUXVpemF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRRdWl6YXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPihgL3F1aXp6ZXMvJHtxdWl6SWR9L2F0dGVtcHRzL2AsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRRdWl6YXR0ZW1wdHMyKHF1aXpJZDogYW55KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUXVpemF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRRdWl6YXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPihgL3F1aXp6ZXMvJHtxdWl6SWR9L2F0dGVtcHRzL2AsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBRdWl6emVzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUXVpenplcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFF1aXp6ZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFF1aXp6ZXNSZXNwb25zZUVudGl0eVtdPignL3F1aXp6ZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFF1aXp6ZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFF1aXp6ZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFF1aXp6ZXNSZXNwb25zZUVudGl0eVtdPignL3F1aXp6ZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIFF1aXpcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlUXVpeihib2R5OiBYLkNyZWF0ZVF1aXpCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlUXVpelJlc3BvbnNlPignL3F1aXp6ZXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgUXVpeiBBdHRlbXB0XG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZVF1aXphdHRlbXB0KHF1aXpJZDogYW55LCBib2R5OiBYLkNyZWF0ZVF1aXphdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVRdWl6YXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVRdWl6YXR0ZW1wdFJlc3BvbnNlPihgL3F1aXp6ZXMvJHtxdWl6SWR9L2F0dGVtcHRzL2AsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVsZXRlIFF1aXpcbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlUXVpeihxdWl6SWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlUXVpelJlc3BvbnNlPihgL3F1aXp6ZXMvJHtxdWl6SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIFF1aXpcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZFF1aXoocXVpeklkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkUXVpelJlc3BvbnNlPihgL3F1aXp6ZXMvJHtxdWl6SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkUXVpejIocXVpeklkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZFF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZFF1aXpSZXNwb25zZT4oYC9xdWl6emVzLyR7cXVpeklkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBRdWl6XG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZVF1aXoocXVpeklkOiBhbnksIGJvZHk6IFguVXBkYXRlUXVpekJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZVF1aXpSZXNwb25zZT4oYC9xdWl6emVzLyR7cXVpeklkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBSZWNhbGwgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcmVjYWxsLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBSZWNhbGxEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIFJlY2FsbCBTZXNzaW9uXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVuZGVyIFJlY2FsbCBTZXNzaW9uIGNvbXBvc2VkIG91dCBvZiB0aGUgc2VxdWVuY2Ugb2YgQ2FyZHMgdGhhdCBzaG91bGQgYmUgcmVjYWxsZWQgaW4gYSBnaXZlbiBvcmRlci4gQmFzZWQgb24gdGhlIFJlY2FsbEF0dGVtcHQgc3RhdHMgcmVjb21tZW5kIGFub3RoZXIgQ2FyZCB0byByZWNhbGwgaW4gb3JkZXIgdG8gbWF4aW1pemUgdGhlIHJlY2FsbCBzcGVlZCBhbmQgc3VjY2VzcyByYXRlLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVSZWNhbGxTZXNzaW9uKGJvZHk6IFguQ3JlYXRlUmVjYWxsU2Vzc2lvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUmVjYWxsU2Vzc2lvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVSZWNhbGxTZXNzaW9uUmVzcG9uc2U+KCcvcmVjYWxsL3Nlc3Npb25zLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBSZWNhbGwgU3VtbWFyeVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgc3VtbWFyeSBzdGF0cyBmb3IgY2FyZHMgYW5kIHRoZWlyIHJlY2FsbF9zY29yZSBmb3IgYSBnaXZlbiBVc2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkUmVjYWxsU3VtbWFyeSgpOiBEYXRhU3RhdGU8WC5SZWFkUmVjYWxsU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkUmVjYWxsU3VtbWFyeVJlc3BvbnNlPignL3JlY2FsbC9zdW1tYXJ5LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZFJlY2FsbFN1bW1hcnkyKCk6IE9ic2VydmFibGU8WC5SZWFkUmVjYWxsU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkUmVjYWxsU3VtbWFyeVJlc3BvbnNlPignL3JlY2FsbC9zdW1tYXJ5LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogU3Vic2NyaXB0aW9uIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3N1YnNjcmlwdGlvbnMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFN1YnNjcmlwdGlvbnNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogUmVxdWVzdCBhIHN1YnNjcmlwdGlvbiBjaGFuZ2VcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBXaGVuZXZlciB0aGUgdXNlciB3YW50cyB0byBjaGFuZ2UgaGVyIHN1YnNjcmlwdGlvbiBpdCBtdXN0IGhhcHBlbiB0aHJvdWdoIHRoaXMgZW5kcG9pbnQuIEl0J3Mgc3RpbGwgcG9zc2libGUgdGhhdCB0aGUgc3Vic2NyaXB0aW9uIHdpbGwgY2hhbmdlIHdpdGhvdXQgdXNlciBhc2tpbmcgZm9yIGl0LCBidXQgdGhhdCBjYW4gaGFwcGVuIHdoZW4gZG93bmdyYWRpbmcgZHVlIHRvIG1pc3NpbmcgcGF5bWVudC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY2hhbmdlU3Vic2NyaXB0aW9uKGJvZHk6IFguQ2hhbmdlU3Vic2NyaXB0aW9uQm9keSk6IE9ic2VydmFibGU8WC5DaGFuZ2VTdWJzY3JpcHRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5DaGFuZ2VTdWJzY3JpcHRpb25SZXNwb25zZT4oJy9wYXltZW50cy9zdWJzY3JpcHRpb24vJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFN1YnNjcmlwdGlvbiBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL3N1YnNjcmlwdGlvbi5weS8jbGluZXMtMjhcbiAqL1xuXG5leHBvcnQgZW51bSBDaGFuZ2VTdWJzY3JpcHRpb25Cb2R5U3Vic2NyaXB0aW9uVHlwZSB7XG4gICAgRlJFRSA9ICdGUkVFJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDaGFuZ2VTdWJzY3JpcHRpb25Cb2R5IHtcbiAgICBzdWJzY3JpcHRpb25fdHlwZTogQ2hhbmdlU3Vic2NyaXB0aW9uQm9keVN1YnNjcmlwdGlvblR5cGU7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3Mvc3Vic2NyaXB0aW9uLnB5LyNsaW5lcy0zOVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2Uge1xuICAgIGF0X19wcm9jZXNzOiBPYmplY3Q7XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBUYXNrcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi90YXNrcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgVGFza3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBUYXNrc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgdGFza3NcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrcyhwYXJhbXM6IFguQnVsa1JlYWRUYXNrc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPignL3Rhc2tzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFRhc2tzMihwYXJhbXM6IFguQnVsa1JlYWRUYXNrc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4oJy90YXNrcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgVGFzayBCaW5zXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBUYXNrcyBCaW5zXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkVGFza0JpbnMocGFyYW1zOiBYLkJ1bGtSZWFkVGFza0JpbnNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4oJy90YXNrcy9iaW5zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFRhc2tCaW5zMihwYXJhbXM6IFguQnVsa1JlYWRUYXNrQmluc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4oJy90YXNrcy9iaW5zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBUYXNrcyBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjLzVmMjE1ZmFiYmE3ZmEzOTI1MTUxYzA5OGZhZDAwNTExNjI0NTI4MjEvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvdGFzay92aWV3cy5weS8jbGluZXMtMzNcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZFRhc2tzUXVlcnlRdWV1ZVR5cGUge1xuICAgIEROID0gJ0ROJyxcbiAgICBIUCA9ICdIUCcsXG4gICAgT1QgPSAnT1QnLFxuICAgIFBSID0gJ1BSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tzUXVlcnkge1xuICAgIGFzY2VuZGluZz86IGJvb2xlYW47XG4gICAgbGltaXQ/OiBudW1iZXI7XG4gICAgb2Zmc2V0PzogbnVtYmVyO1xuICAgIHF1ZXVlX3R5cGU/OiBCdWxrUmVhZFRhc2tzUXVlcnlRdWV1ZVR5cGU7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvNWYyMTVmYWJiYTdmYTM5MjUxNTFjMDk4ZmFkMDA1MTE2MjQ1MjgyMS9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS90YXNrL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy01NVxuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkVGFza3NSZXNwb25zZVF1ZXVlVHlwZSB7XG4gICAgRE4gPSAnRE4nLFxuICAgIEhQID0gJ0hQJyxcbiAgICBPVCA9ICdPVCcsXG4gICAgUFIgPSAnUFInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eSB7XG4gICAgYXJjaGl2ZWQ/OiBib29sZWFuO1xuICAgIGNvbnRlbnQ/OiBPYmplY3Q7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBkb25lX2RhdGU6IHN0cmluZztcbiAgICBkb25lX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIG9yZGVyX251bWJlcj86IG51bWJlcjtcbiAgICBxdWV1ZV90eXBlPzogQnVsa1JlYWRUYXNrc1Jlc3BvbnNlUXVldWVUeXBlO1xuICAgIHRvdGFsX3RpbWU/OiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrc1Jlc3BvbnNlIHtcbiAgICB0YXNrczogQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvNWYyMTVmYWJiYTdmYTM5MjUxNTFjMDk4ZmFkMDA1MTE2MjQ1MjgyMS9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS90YXNrL3ZpZXdzLnB5LyNsaW5lcy0zM1xuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkVGFza0JpbnNRdWVyeVF1ZXVlVHlwZSB7XG4gICAgRE4gPSAnRE4nLFxuICAgIEhQID0gJ0hQJyxcbiAgICBPVCA9ICdPVCcsXG4gICAgUFIgPSAnUFInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza0JpbnNRdWVyeSB7XG4gICAgYXNjZW5kaW5nPzogYm9vbGVhbjtcbiAgICBsaW1pdD86IG51bWJlcjtcbiAgICBvZmZzZXQ/OiBudW1iZXI7XG4gICAgcXVldWVfdHlwZT86IEJ1bGtSZWFkVGFza0JpbnNRdWVyeVF1ZXVlVHlwZTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy81ZjIxNWZhYmJhN2ZhMzkyNTE1MWMwOThmYWQwMDUxMTYyNDUyODIxL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL3Rhc2svc2VyaWFsaXplcnMucHkvI2xpbmVzLTcxXG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlUXVldWVUeXBlIHtcbiAgICBETiA9ICdETicsXG4gICAgSFAgPSAnSFAnLFxuICAgIE9UID0gJ09UJyxcbiAgICBQUiA9ICdQUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBkb25lX2RhdGU6IHN0cmluZztcbiAgICB0YXNrczoge1xuICAgICAgICBhcmNoaXZlZD86IGJvb2xlYW47XG4gICAgICAgIGNvbnRlbnQ/OiBPYmplY3Q7XG4gICAgICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgICAgIGRvbmVfZGF0ZTogc3RyaW5nO1xuICAgICAgICBkb25lX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgICAgICBpZD86IG51bWJlcjtcbiAgICAgICAgb3JkZXJfbnVtYmVyPzogbnVtYmVyO1xuICAgICAgICBxdWV1ZV90eXBlPzogQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlUXVldWVUeXBlO1xuICAgICAgICB0b3RhbF90aW1lPzogbnVtYmVyO1xuICAgIH1bXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2Uge1xuICAgIHRhc2tzX2JpbnM6IEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogV29yZHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vd29yZHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFdvcmRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgV29yZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFdvcmRzIGJ5IGZpcnN0IGNoYXJhY3Rlci4gSXQgYWxsb3dzIG9uZSB0byBmZXRjaCBsaXN0IG9mIHdvcmRzIGJ5IGZpcnN0IGNoYXJhY3Rlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPignL3dvcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRXb3Jkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRmFjYWRlIEFQSSBTZXJ2aWNlIGZvciBhbGwgZG9tYWluc1xuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlLCBJbmplY3RvciB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuXG5pbXBvcnQgeyBEYXRhU3RhdGUsIE9wdGlvbnMgfSBmcm9tICcuL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4uL2RvbWFpbnMvaW5kZXgnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQVBJU2VydmljZSB7XG5cbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGluamVjdG9yOiBJbmplY3Rvcikge31cblxuICAgIC8qKlxuICAgICAqIEFjY291bnQgU2V0dGluZ3MgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hY2NvdW50X3NldHRpbmdzRG9tYWluOiBYLkFjY291bnRTZXR0aW5nc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGFjY291bnRfc2V0dGluZ3NEb21haW4oKTogWC5BY2NvdW50U2V0dGluZ3NEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2FjY291bnRfc2V0dGluZ3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2FjY291bnRfc2V0dGluZ3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkFjY291bnRTZXR0aW5nc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2FjY291bnRfc2V0dGluZ3NEb21haW47XG4gICAgfVxuXG4gICAgcmVhZEFjY291bnRzZXR0aW5nKCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRfc2V0dGluZ3NEb21haW4ucmVhZEFjY291bnRzZXR0aW5nKCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRBY2NvdW50c2V0dGluZzIoKTogT2JzZXJ2YWJsZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRfc2V0dGluZ3NEb21haW4ucmVhZEFjY291bnRzZXR0aW5nMigpO1xuICAgIH1cblxuICAgIHVwZGF0ZUFjY291bnRzZXR0aW5nKGJvZHk6IFguVXBkYXRlQWNjb3VudHNldHRpbmdCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRzZXR0aW5nUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudF9zZXR0aW5nc0RvbWFpbi51cGRhdGVBY2NvdW50c2V0dGluZyhib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBY2NvdW50cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2FjY291bnRzRG9tYWluOiBYLkFjY291bnRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYWNjb3VudHNEb21haW4oKTogWC5BY2NvdW50c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fYWNjb3VudHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2FjY291bnRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5BY2NvdW50c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2FjY291bnRzRG9tYWluO1xuICAgIH1cblxuICAgIGFjdGl2YXRlQWNjb3VudChib2R5OiBYLkFjdGl2YXRlQWNjb3VudEJvZHkpOiBPYnNlcnZhYmxlPFguQWN0aXZhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uYWN0aXZhdGVBY2NvdW50KGJvZHkpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkQWNjb3VudHMocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLmJ1bGtSZWFkQWNjb3VudHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRBY2NvdW50czIocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5idWxrUmVhZEFjY291bnRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNoYW5nZVBhc3N3b3JkKGJvZHk6IFguQ2hhbmdlUGFzc3dvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNoYW5nZVBhc3N3b3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uY2hhbmdlUGFzc3dvcmQoYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlQWNjb3VudChib2R5OiBYLkNyZWF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5jcmVhdGVBY2NvdW50KGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRBY2NvdW50KCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4ucmVhZEFjY291bnQoKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEFjY291bnQyKCk6IE9ic2VydmFibGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnJlYWRBY2NvdW50MigpO1xuICAgIH1cblxuICAgIHJlc2V0UGFzc3dvcmQoYm9keTogWC5SZXNldFBhc3N3b3JkQm9keSk6IE9ic2VydmFibGU8WC5SZXNldFBhc3N3b3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4ucmVzZXRQYXNzd29yZChib2R5KTtcbiAgICB9XG5cbiAgICBzZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbChib2R5OiBYLlNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsQm9keSk6IE9ic2VydmFibGU8WC5TZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsKGJvZHkpO1xuICAgIH1cblxuICAgIHNlbmRSZXNldFBhc3N3b3JkRW1haWwoYm9keTogWC5TZW5kUmVzZXRQYXNzd29yZEVtYWlsQm9keSk6IE9ic2VydmFibGU8WC5TZW5kUmVzZXRQYXNzd29yZEVtYWlsUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uc2VuZFJlc2V0UGFzc3dvcmRFbWFpbChib2R5KTtcbiAgICB9XG5cbiAgICB1cGRhdGVBY2NvdW50KGJvZHk6IFguVXBkYXRlQWNjb3VudEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnVwZGF0ZUFjY291bnQoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQXR0ZW1wdCBTdGF0cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2F0dGVtcHRfc3RhdHNEb21haW46IFguQXR0ZW1wdFN0YXRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYXR0ZW1wdF9zdGF0c0RvbWFpbigpOiBYLkF0dGVtcHRTdGF0c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fYXR0ZW1wdF9zdGF0c0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fYXR0ZW1wdF9zdGF0c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQXR0ZW1wdFN0YXRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fYXR0ZW1wdF9zdGF0c0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEF0dGVtcHRzdGF0cyhwYXJhbXM6IFguQnVsa1JlYWRBdHRlbXB0c3RhdHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdF9zdGF0c0RvbWFpbi5idWxrUmVhZEF0dGVtcHRzdGF0cyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEF0dGVtcHRzdGF0czIocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0X3N0YXRzRG9tYWluLmJ1bGtSZWFkQXR0ZW1wdHN0YXRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUF0dGVtcHRzdGF0KGJvZHk6IFguQ3JlYXRlQXR0ZW1wdHN0YXRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUF0dGVtcHRzdGF0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdF9zdGF0c0RvbWFpbi5jcmVhdGVBdHRlbXB0c3RhdChib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0KGJvZHk6IFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRfc3RhdHNEb21haW4uY3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdChib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBdHRlbXB0cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2F0dGVtcHRzRG9tYWluOiBYLkF0dGVtcHRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYXR0ZW1wdHNEb21haW4oKTogWC5BdHRlbXB0c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fYXR0ZW1wdHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2F0dGVtcHRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5BdHRlbXB0c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2F0dGVtcHRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRzRG9tYWluLmJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzKGNhcmRJZCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzMihjYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdHNEb21haW4uYnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHMyKGNhcmRJZCk7XG4gICAgfVxuXG4gICAgY3JlYXRlQXR0ZW1wdChib2R5OiBYLkNyZWF0ZUF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0c0RvbWFpbi5jcmVhdGVBdHRlbXB0KGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZUF0dGVtcHQoYXR0ZW1wdElkOiBhbnksIGJvZHk6IFguVXBkYXRlQXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRzRG9tYWluLnVwZGF0ZUF0dGVtcHQoYXR0ZW1wdElkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBdXRoIFRva2VucyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2F1dGhfdG9rZW5zRG9tYWluOiBYLkF1dGhUb2tlbnNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBhdXRoX3Rva2Vuc0RvbWFpbigpOiBYLkF1dGhUb2tlbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2F1dGhfdG9rZW5zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hdXRoX3Rva2Vuc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQXV0aFRva2Vuc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2F1dGhfdG9rZW5zRG9tYWluO1xuICAgIH1cblxuICAgIGF1dGhvcml6ZUF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguQXV0aG9yaXplQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uYXV0aG9yaXplQXV0aFRva2VuKCk7XG4gICAgfVxuXG4gICAgY3JlYXRlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi5jcmVhdGVBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi5jcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlR29vZ2xlQmFzZWRNb2JpbGVBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlR29vZ2xlQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgdXBkYXRlQXV0aFRva2VuKCk6IE9ic2VydmFibGU8WC5VcGRhdGVBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi51cGRhdGVBdXRoVG9rZW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCcmlja3MgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9icmlja3NEb21haW46IFguQnJpY2tzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYnJpY2tzRG9tYWluKCk6IFguQnJpY2tzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9icmlja3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2JyaWNrc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQnJpY2tzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fYnJpY2tzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkR2FtZWF0dGVtcHRzKGdhbWVJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRHYW1lYXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi5idWxrUmVhZEdhbWVhdHRlbXB0cyhnYW1lSWQpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEdhbWVhdHRlbXB0czIoZ2FtZUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRHYW1lYXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi5idWxrUmVhZEdhbWVhdHRlbXB0czIoZ2FtZUlkKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZEdhbWVzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2FtZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi5idWxrUmVhZEdhbWVzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkR2FtZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEdhbWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4uYnVsa1JlYWRHYW1lczIoKTtcbiAgICB9XG5cbiAgICBjcmVhdGVHYW1lKGJvZHk6IFguQ3JlYXRlR2FtZUJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi5jcmVhdGVHYW1lKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUdhbWVhdHRlbXB0KGdhbWVJZDogYW55LCBib2R5OiBYLkNyZWF0ZUdhbWVhdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVHYW1lYXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi5jcmVhdGVHYW1lYXR0ZW1wdChnYW1lSWQsIGJvZHkpO1xuICAgIH1cblxuICAgIGRlbGV0ZUdhbWUoZ2FtZUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi5kZWxldGVHYW1lKGdhbWVJZCk7XG4gICAgfVxuXG4gICAgcmVhZEdhbWUoZ2FtZUlkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi5yZWFkR2FtZShnYW1lSWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkR2FtZTIoZ2FtZUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEdhbWVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4ucmVhZEdhbWUyKGdhbWVJZCk7XG4gICAgfVxuXG4gICAgdXBkYXRlR2FtZShnYW1lSWQ6IGFueSwgYm9keTogWC5VcGRhdGVHYW1lQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVHYW1lUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYnJpY2tzRG9tYWluLnVwZGF0ZUdhbWUoZ2FtZUlkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2NhcmRzRG9tYWluOiBYLkNhcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgY2FyZHNEb21haW4oKTogWC5DYXJkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fY2FyZHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2NhcmRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5DYXJkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2NhcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtEZWxldGVDYXJkcyhwYXJhbXM6IFguQnVsa0RlbGV0ZUNhcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4uYnVsa0RlbGV0ZUNhcmRzKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRDYXJkcyhwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4uYnVsa1JlYWRDYXJkcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZENhcmRzMihwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLmJ1bGtSZWFkQ2FyZHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlQ2FyZChib2R5OiBYLkNyZWF0ZUNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5jcmVhdGVDYXJkKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRDYXJkKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5yZWFkQ2FyZChjYXJkSWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkQ2FyZDIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5yZWFkQ2FyZDIoY2FyZElkKTtcbiAgICB9XG5cbiAgICB1cGRhdGVDYXJkKGNhcmRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi51cGRhdGVDYXJkKGNhcmRJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2F0ZWdvcmllcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2NhdGVnb3JpZXNEb21haW46IFguQ2F0ZWdvcmllc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGNhdGVnb3JpZXNEb21haW4oKTogWC5DYXRlZ29yaWVzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9jYXRlZ29yaWVzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9jYXRlZ29yaWVzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5DYXRlZ29yaWVzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fY2F0ZWdvcmllc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZENhdGVnb3JpZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXRlZ29yaWVzRG9tYWluLmJ1bGtSZWFkQ2F0ZWdvcmllcygpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZENhdGVnb3JpZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhdGVnb3JpZXNEb21haW4uYnVsa1JlYWRDYXRlZ29yaWVzMigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnRhY3QgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9jb250YWN0c0RvbWFpbjogWC5Db250YWN0c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGNvbnRhY3RzRG9tYWluKCk6IFguQ29udGFjdHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2NvbnRhY3RzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9jb250YWN0c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQ29udGFjdHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9jb250YWN0c0RvbWFpbjtcbiAgICB9XG5cbiAgICBjcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLkNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbnRhY3RzRG9tYWluLmNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHkpO1xuICAgIH1cblxuICAgIHNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2UoYm9keTogWC5TZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlQm9keSk6IE9ic2VydmFibGU8WC5TZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29udGFjdHNEb21haW4uc2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZShib2R5KTtcbiAgICB9XG5cbiAgICB2ZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLlZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbnRhY3RzRG9tYWluLnZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERvbmF0aW9ucyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2RvbmF0aW9uc0RvbWFpbjogWC5Eb25hdGlvbnNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBkb25hdGlvbnNEb21haW4oKTogWC5Eb25hdGlvbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2RvbmF0aW9uc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZG9uYXRpb25zRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Eb25hdGlvbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9kb25hdGlvbnNEb21haW47XG4gICAgfVxuXG4gICAgY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbihwYXJhbXM6IFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5KTogRGF0YVN0YXRlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmRvbmF0aW9uc0RvbWFpbi5jaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb24yKHBhcmFtczogWC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnkpOiBPYnNlcnZhYmxlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmRvbmF0aW9uc0RvbWFpbi5jaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUFub255bW91c0RvbmF0aW9uKGJvZHk6IFguQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNyZWF0ZUFub255bW91c0RvbmF0aW9uKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZURvbmF0aW9uKGJvZHk6IFguQ3JlYXRlRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNyZWF0ZURvbmF0aW9uKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZURvbmF0aW9uYXR0ZW1wdChib2R5OiBYLkNyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNyZWF0ZURvbmF0aW9uYXR0ZW1wdChib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFeHRlcm5hbCBBcHBzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZXh0ZXJuYWxfYXBwc0RvbWFpbjogWC5FeHRlcm5hbEFwcHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBleHRlcm5hbF9hcHBzRG9tYWluKCk6IFguRXh0ZXJuYWxBcHBzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9leHRlcm5hbF9hcHBzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9leHRlcm5hbF9hcHBzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5FeHRlcm5hbEFwcHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9leHRlcm5hbF9hcHBzRG9tYWluO1xuICAgIH1cblxuICAgIGF1dGhvcml6ZUV4dGVybmFsQXBwQXV0aFRva2VuKCk6IE9ic2VydmFibGU8WC5BdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmV4dGVybmFsX2FwcHNEb21haW4uYXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW4oKTtcbiAgICB9XG5cbiAgICBjcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmV4dGVybmFsX2FwcHNEb21haW4uY3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZEV4dGVybmFsYXBwY29uZihwYXJhbXM6IFguUmVhZEV4dGVybmFsYXBwY29uZlF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmV4dGVybmFsX2FwcHNEb21haW4ucmVhZEV4dGVybmFsYXBwY29uZihwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICByZWFkRXh0ZXJuYWxhcHBjb25mMihwYXJhbXM6IFguUmVhZEV4dGVybmFsYXBwY29uZlF1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5leHRlcm5hbF9hcHBzRG9tYWluLnJlYWRFeHRlcm5hbGFwcGNvbmYyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRm9jdXMgUmVjb3JkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ZvY3VzX3JlY29yZHNEb21haW46IFguRm9jdXNSZWNvcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZm9jdXNfcmVjb3Jkc0RvbWFpbigpOiBYLkZvY3VzUmVjb3Jkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZm9jdXNfcmVjb3Jkc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZm9jdXNfcmVjb3Jkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRm9jdXNSZWNvcmRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZm9jdXNfcmVjb3Jkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBjcmVhdGVGb2N1c3JlY29yZChib2R5OiBYLkNyZWF0ZUZvY3VzcmVjb3JkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGb2N1c3JlY29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZvY3VzX3JlY29yZHNEb21haW4uY3JlYXRlRm9jdXNyZWNvcmQoYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZEZvY3VzUmVjb3JkU3VtbWFyeSgpOiBEYXRhU3RhdGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZm9jdXNfcmVjb3Jkc0RvbWFpbi5yZWFkRm9jdXNSZWNvcmRTdW1tYXJ5KCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRGb2N1c1JlY29yZFN1bW1hcnkyKCk6IE9ic2VydmFibGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZm9jdXNfcmVjb3Jkc0RvbWFpbi5yZWFkRm9jdXNSZWNvcmRTdW1tYXJ5MigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEZyYWdtZW50IEhhc2h0YWdzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZnJhZ21lbnRfaGFzaHRhZ3NEb21haW46IFguRnJhZ21lbnRIYXNodGFnc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGZyYWdtZW50X2hhc2h0YWdzRG9tYWluKCk6IFguRnJhZ21lbnRIYXNodGFnc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ZyYWdtZW50X2hhc2h0YWdzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5GcmFnbWVudEhhc2h0YWdzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZnJhZ21lbnRfaGFzaHRhZ3NEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X2hhc2h0YWdzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFncyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X2hhc2h0YWdzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBGcmFnbWVudCBXb3JkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ZyYWdtZW50X3dvcmRzRG9tYWluOiBYLkZyYWdtZW50V29yZHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBmcmFnbWVudF93b3Jkc0RvbWFpbigpOiBYLkZyYWdtZW50V29yZHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2ZyYWdtZW50X3dvcmRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9mcmFnbWVudF93b3Jkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRnJhZ21lbnRXb3Jkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ZyYWdtZW50X3dvcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X3dvcmRzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRXb3JkcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEZyYWdtZW50V29yZHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50V29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X3dvcmRzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRXb3JkczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF93b3Jkc0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF93b3Jkc0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRnJhZ21lbnRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZnJhZ21lbnRzRG9tYWluOiBYLkZyYWdtZW50c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGZyYWdtZW50c0RvbWFpbigpOiBYLkZyYWdtZW50c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZnJhZ21lbnRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9mcmFnbWVudHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkZyYWdtZW50c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ZyYWdtZW50c0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEZyYWdtZW50cyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uYnVsa1JlYWRGcmFnbWVudHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uYnVsa1JlYWRGcmFnbWVudHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUZyYWdtZW50KCk6IE9ic2VydmFibGU8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5jcmVhdGVGcmFnbWVudCgpO1xuICAgIH1cblxuICAgIGRlbGV0ZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5kZWxldGVGcmFnbWVudChmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICBtZXJnZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5NZXJnZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLm1lcmdlRnJhZ21lbnQoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgcHVibGlzaEZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5QdWJsaXNoRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucHVibGlzaEZyYWdtZW50KGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIHJlYWRGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50KGZyYWdtZW50SWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkRnJhZ21lbnQyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50MihmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICByZWFkRnJhZ21lbnREaWZmKGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50RGlmZihmcmFnbWVudElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEZyYWdtZW50RGlmZjIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50RGlmZjIoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgcmVhZEZyYWdtZW50U2FtcGxlKGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnRTYW1wbGUoZnJhZ21lbnRJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRGcmFnbWVudFNhbXBsZTIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnRTYW1wbGUyKGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIHVwZGF0ZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSwgYm9keTogWC5VcGRhdGVGcmFnbWVudEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4udXBkYXRlRnJhZ21lbnQoZnJhZ21lbnRJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2VvbWV0cmllcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2dlb21ldHJpZXNEb21haW46IFguR2VvbWV0cmllc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGdlb21ldHJpZXNEb21haW4oKTogWC5HZW9tZXRyaWVzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9nZW9tZXRyaWVzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9nZW9tZXRyaWVzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5HZW9tZXRyaWVzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZ2VvbWV0cmllc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEdlb21ldHJpZXMocGFyYW1zOiBYLkJ1bGtSZWFkR2VvbWV0cmllc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLmJ1bGtSZWFkR2VvbWV0cmllcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEdlb21ldHJpZXMyKHBhcmFtczogWC5CdWxrUmVhZEdlb21ldHJpZXNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEdlb21ldHJpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4uYnVsa1JlYWRHZW9tZXRyaWVzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtVcGRhdGVHZW9tZXRyaWVzKGJvZHk6IFguQnVsa1VwZGF0ZUdlb21ldHJpZXNCb2R5KTogT2JzZXJ2YWJsZTxYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5idWxrVXBkYXRlR2VvbWV0cmllcyhib2R5KTtcbiAgICB9XG5cbiAgICByZWFkR2VvbWV0cnlCeUNhcmQoY2FyZElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLnJlYWRHZW9tZXRyeUJ5Q2FyZChjYXJkSWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkR2VvbWV0cnlCeUNhcmQyKGNhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4ucmVhZEdlb21ldHJ5QnlDYXJkMihjYXJkSWQpO1xuICAgIH1cblxuICAgIHJlYWRHcmFwaChwYXJhbXM6IFguUmVhZEdyYXBoUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkR3JhcGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLnJlYWRHcmFwaChwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICByZWFkR3JhcGgyKHBhcmFtczogWC5SZWFkR3JhcGhRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkR3JhcGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLnJlYWRHcmFwaDIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHb3NzaXAgQ29tbWFuZHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9nb3NzaXBEb21haW46IFguR29zc2lwRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZ29zc2lwRG9tYWluKCk6IFguR29zc2lwRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9nb3NzaXBEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2dvc3NpcERvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguR29zc2lwRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZ29zc2lwRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nb3NzaXBEb21haW4uYnVsa1JlYWRTcGVlY2hMYW5ndWFnZXMoKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRTcGVlY2hMYW5ndWFnZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFNwZWVjaExhbmd1YWdlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ29zc2lwRG9tYWluLmJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzMigpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkVGV4dExhbmd1YWdlcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRleHRMYW5ndWFnZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdvc3NpcERvbWFpbi5idWxrUmVhZFRleHRMYW5ndWFnZXMoKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRUZXh0TGFuZ3VhZ2VzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUZXh0TGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nb3NzaXBEb21haW4uYnVsa1JlYWRUZXh0TGFuZ3VhZ2VzMigpO1xuICAgIH1cblxuICAgIGRldGVjdFNwZWVjaExhbmd1YWdlcyhib2R5OiBYLkRldGVjdFNwZWVjaExhbmd1YWdlc0JvZHkpOiBPYnNlcnZhYmxlPFguRGV0ZWN0U3BlZWNoTGFuZ3VhZ2VzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ29zc2lwRG9tYWluLmRldGVjdFNwZWVjaExhbmd1YWdlcyhib2R5KTtcbiAgICB9XG5cbiAgICBkZXRlY3RUZXh0TGFuZ3VhZ2VzKGJvZHk6IFguRGV0ZWN0VGV4dExhbmd1YWdlc0JvZHkpOiBPYnNlcnZhYmxlPFguRGV0ZWN0VGV4dExhbmd1YWdlc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdvc3NpcERvbWFpbi5kZXRlY3RUZXh0TGFuZ3VhZ2VzKGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEhhc2h0YWdzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfaGFzaHRhZ3NEb21haW46IFguSGFzaHRhZ3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBoYXNodGFnc0RvbWFpbigpOiBYLkhhc2h0YWdzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9oYXNodGFnc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5faGFzaHRhZ3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkhhc2h0YWdzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5faGFzaHRhZ3NEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRIYXNodGFncyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLmJ1bGtSZWFkSGFzaHRhZ3MyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlSGFzaHRhZyhib2R5OiBYLkNyZWF0ZUhhc2h0YWdCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5jcmVhdGVIYXNodGFnKGJvZHkpO1xuICAgIH1cblxuICAgIGRlbGV0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIHBhcmFtczogWC5EZWxldGVIYXNodGFnUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLmRlbGV0ZUhhc2h0YWcoaGFzaHRhZ0lkLCBwYXJhbXMpO1xuICAgIH1cblxuICAgIHJlYWRIYXNodGFnc1RvYyhwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5yZWFkSGFzaHRhZ3NUb2MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEhhc2h0YWdzVG9jMihwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4ucmVhZEhhc2h0YWdzVG9jMihwYXJhbXMpO1xuICAgIH1cblxuICAgIHVwZGF0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIGJvZHk6IFguVXBkYXRlSGFzaHRhZ0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLnVwZGF0ZUhhc2h0YWcoaGFzaHRhZ0lkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBJbnZvaWNlIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfaW52b2ljZXNEb21haW46IFguSW52b2ljZXNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBpbnZvaWNlc0RvbWFpbigpOiBYLkludm9pY2VzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9pbnZvaWNlc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5faW52b2ljZXNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkludm9pY2VzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5faW52b2ljZXNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRJbnZvaWNlcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5idWxrUmVhZEludm9pY2VzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkSW52b2ljZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5idWxrUmVhZEludm9pY2VzMigpO1xuICAgIH1cblxuICAgIGNhbGN1bGF0ZURlYnQoKTogRGF0YVN0YXRlPFguQ2FsY3VsYXRlRGVidFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmludm9pY2VzRG9tYWluLmNhbGN1bGF0ZURlYnQoKTtcbiAgICB9XG4gICAgXG4gICAgY2FsY3VsYXRlRGVidDIoKTogT2JzZXJ2YWJsZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5jYWxjdWxhdGVEZWJ0MigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbmtzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfbGlua3NEb21haW46IFguTGlua3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBsaW5rc0RvbWFpbigpOiBYLkxpbmtzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9saW5rc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fbGlua3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkxpbmtzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fbGlua3NEb21haW47XG4gICAgfVxuXG4gICAgZGVsZXRlTGluayhmcm9tQ2FyZElkOiBhbnksIHRvQ2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlTGlua1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmxpbmtzRG9tYWluLmRlbGV0ZUxpbmsoZnJvbUNhcmRJZCwgdG9DYXJkSWQpO1xuICAgIH1cblxuICAgIHJlYWRPckNyZWF0ZUxpbmsoYm9keTogWC5SZWFkT3JDcmVhdGVMaW5rQm9keSk6IE9ic2VydmFibGU8WC5SZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubGlua3NEb21haW4ucmVhZE9yQ3JlYXRlTGluayhib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNZWRpYUl0ZW1zIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfbWVkaWFpdGVtc0RvbWFpbjogWC5NZWRpYWl0ZW1zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgbWVkaWFpdGVtc0RvbWFpbigpOiBYLk1lZGlhaXRlbXNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX21lZGlhaXRlbXNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX21lZGlhaXRlbXNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLk1lZGlhaXRlbXNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9tZWRpYWl0ZW1zRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkTWVkaWFpdGVtcyhwYXJhbXM6IFguQnVsa1JlYWRNZWRpYWl0ZW1zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4uYnVsa1JlYWRNZWRpYWl0ZW1zKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkTWVkaWFpdGVtczIocGFyYW1zOiBYLkJ1bGtSZWFkTWVkaWFpdGVtc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkTWVkaWFpdGVtc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5idWxrUmVhZE1lZGlhaXRlbXMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgZGVsZXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnksIHBhcmFtczogWC5EZWxldGVNZWRpYWl0ZW1RdWVyeSk6IE9ic2VydmFibGU8WC5EZWxldGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLmRlbGV0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZCwgcGFyYW1zKTtcbiAgICB9XG5cbiAgICByZWFkTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5yZWFkTWVkaWFpdGVtKG1lZGlhaXRlbUlkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZE1lZGlhaXRlbTIobWVkaWFpdGVtSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5yZWFkTWVkaWFpdGVtMihtZWRpYWl0ZW1JZCk7XG4gICAgfVxuXG4gICAgcmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkKCk6IERhdGFTdGF0ZTxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkKCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZDIoKTogT2JzZXJ2YWJsZTxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkMigpO1xuICAgIH1cblxuICAgIHJlYWRPckNyZWF0ZU1lZGlhaXRlbShib2R5OiBYLlJlYWRPckNyZWF0ZU1lZGlhaXRlbUJvZHkpOiBPYnNlcnZhYmxlPFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5yZWFkT3JDcmVhdGVNZWRpYWl0ZW0oYm9keSk7XG4gICAgfVxuXG4gICAgdXBkYXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnksIGJvZHk6IFguVXBkYXRlTWVkaWFpdGVtQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLnVwZGF0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZCwgYm9keSk7XG4gICAgfVxuXG4gICAgdXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb24obWVkaWFpdGVtSWQ6IGFueSwgYm9keTogWC5VcGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLnVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uKG1lZGlhaXRlbUlkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBOb3RpZmljYXRpb24gTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9ub3RpZmljYXRpb25zRG9tYWluOiBYLk5vdGlmaWNhdGlvbnNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBub3RpZmljYXRpb25zRG9tYWluKCk6IFguTm90aWZpY2F0aW9uc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fbm90aWZpY2F0aW9uc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fbm90aWZpY2F0aW9uc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguTm90aWZpY2F0aW9uc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX25vdGlmaWNhdGlvbnNEb21haW47XG4gICAgfVxuXG4gICAgYWNrbm93bGVkZ2VOb3RpZmljYXRpb24obm90aWZpY2F0aW9uSWQ6IGFueSk6IE9ic2VydmFibGU8WC5BY2tub3dsZWRnZU5vdGlmaWNhdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm5vdGlmaWNhdGlvbnNEb21haW4uYWNrbm93bGVkZ2VOb3RpZmljYXRpb24obm90aWZpY2F0aW9uSWQpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkTm90aWZpY2F0aW9ucyhwYXJhbXM6IFguQnVsa1JlYWROb3RpZmljYXRpb25zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm5vdGlmaWNhdGlvbnNEb21haW4uYnVsa1JlYWROb3RpZmljYXRpb25zKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkTm90aWZpY2F0aW9uczIocGFyYW1zOiBYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubm90aWZpY2F0aW9uc0RvbWFpbi5idWxrUmVhZE5vdGlmaWNhdGlvbnMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTm91bnMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9ub3Vuc0RvbWFpbjogWC5Ob3Vuc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IG5vdW5zRG9tYWluKCk6IFguTm91bnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX25vdW5zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9ub3Vuc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguTm91bnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9ub3Vuc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEljb25zKHBhcmFtczogWC5CdWxrUmVhZEljb25zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEljb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5ub3Vuc0RvbWFpbi5idWxrUmVhZEljb25zKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkSWNvbnMyKHBhcmFtczogWC5CdWxrUmVhZEljb25zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRJY29uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubm91bnNEb21haW4uYnVsa1JlYWRJY29uczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQYXRocyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3BhdGhzRG9tYWluOiBYLlBhdGhzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcGF0aHNEb21haW4oKTogWC5QYXRoc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcGF0aHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3BhdGhzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5QYXRoc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3BhdGhzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtEZWxldGVQYXRocyhwYXJhbXM6IFguQnVsa0RlbGV0ZVBhdGhzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa0RlbGV0ZVBhdGhzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4uYnVsa0RlbGV0ZVBhdGhzKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRQYXRocyhwYXJhbXM6IFguQnVsa1JlYWRQYXRoc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4uYnVsa1JlYWRQYXRocyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFBhdGhzMihwYXJhbXM6IFguQnVsa1JlYWRQYXRoc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLmJ1bGtSZWFkUGF0aHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlUGF0aChib2R5OiBYLkNyZWF0ZVBhdGhCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5jcmVhdGVQYXRoKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRQYXRoKHBhdGhJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZFBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5yZWFkUGF0aChwYXRoSWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkUGF0aDIocGF0aElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZFBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5yZWFkUGF0aDIocGF0aElkKTtcbiAgICB9XG5cbiAgICB1cGRhdGVQYXRoKHBhdGhJZDogYW55LCBib2R5OiBYLlVwZGF0ZVBhdGhCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi51cGRhdGVQYXRoKHBhdGhJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUGF5bWVudCBDYXJkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3BheW1lbnRfY2FyZHNEb21haW46IFguUGF5bWVudENhcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcGF5bWVudF9jYXJkc0RvbWFpbigpOiBYLlBheW1lbnRDYXJkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcGF5bWVudF9jYXJkc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcGF5bWVudF9jYXJkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguUGF5bWVudENhcmRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fcGF5bWVudF9jYXJkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBhc0RlZmF1bHRNYXJrUGF5bWVudGNhcmQocGF5bWVudENhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uYXNEZWZhdWx0TWFya1BheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUGF5bWVudGNhcmRzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLmJ1bGtSZWFkUGF5bWVudGNhcmRzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUGF5bWVudGNhcmRzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uYnVsa1JlYWRQYXltZW50Y2FyZHMyKCk7XG4gICAgfVxuXG4gICAgY3JlYXRlUGF5bWVudGNhcmQoYm9keTogWC5DcmVhdGVQYXltZW50Y2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLmNyZWF0ZVBheW1lbnRjYXJkKGJvZHkpO1xuICAgIH1cblxuICAgIGRlbGV0ZVBheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uZGVsZXRlUGF5bWVudGNhcmQocGF5bWVudENhcmRJZCk7XG4gICAgfVxuXG4gICAgcGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZChib2R5OiBYLlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLnBheVdpdGhEZWZhdWx0UGF5bWVudENhcmQoYm9keSk7XG4gICAgfVxuXG4gICAgcmVuZGVyUGF5bWVudENhcmRXaWRnZXQoKTogRGF0YVN0YXRlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLnJlbmRlclBheW1lbnRDYXJkV2lkZ2V0KCk7XG4gICAgfVxuICAgIFxuICAgIHJlbmRlclBheW1lbnRDYXJkV2lkZ2V0MigpOiBPYnNlcnZhYmxlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLnJlbmRlclBheW1lbnRDYXJkV2lkZ2V0MigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBheW1lbnRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfcGF5bWVudHNEb21haW46IFguUGF5bWVudHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBwYXltZW50c0RvbWFpbigpOiBYLlBheW1lbnRzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wYXltZW50c0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcGF5bWVudHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlBheW1lbnRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fcGF5bWVudHNEb21haW47XG4gICAgfVxuXG4gICAgdXBkYXRlUGF5bWVudFN0YXR1cyhib2R5OiBYLlVwZGF0ZVBheW1lbnRTdGF0dXNCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVBheW1lbnRTdGF0dXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50c0RvbWFpbi51cGRhdGVQYXltZW50U3RhdHVzKGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFByb2Nlc3NlcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3Byb2Nlc3Nlc0RvbWFpbjogWC5Qcm9jZXNzZXNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBwcm9jZXNzZXNEb21haW4oKTogWC5Qcm9jZXNzZXNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3Byb2Nlc3Nlc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcHJvY2Vzc2VzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Qcm9jZXNzZXNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9wcm9jZXNzZXNEb21haW47XG4gICAgfVxuXG4gICAgY3JlYXRlRGVsZXRpb25Qcm9jZXNzKGJvZHk6IFguQ3JlYXRlRGVsZXRpb25Qcm9jZXNzQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEZWxldGlvblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4uY3JlYXRlRGVsZXRpb25Qcm9jZXNzKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZURvd25sb2FkUHJvY2Vzcyhib2R5OiBYLkNyZWF0ZURvd25sb2FkUHJvY2Vzc0JvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRG93bmxvYWRQcm9jZXNzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc2VzRG9tYWluLmNyZWF0ZURvd25sb2FkUHJvY2Vzcyhib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVNZWRpYUxvY2soYm9keTogWC5DcmVhdGVNZWRpYUxvY2tCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZU1lZGlhTG9ja1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi5jcmVhdGVNZWRpYUxvY2soYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlVXBsb2FkUHJvY2Vzcyhib2R5OiBYLkNyZWF0ZVVwbG9hZFByb2Nlc3NCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVVwbG9hZFByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4uY3JlYXRlVXBsb2FkUHJvY2Vzcyhib2R5KTtcbiAgICB9XG5cbiAgICByZWFkSW52YXJpYW50cyhwYXJhbXM6IFguUmVhZEludmFyaWFudHNRdWVyeSk6IERhdGFTdGF0ZTxYLlJlYWRJbnZhcmlhbnRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc2VzRG9tYWluLnJlYWRJbnZhcmlhbnRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRJbnZhcmlhbnRzMihwYXJhbXM6IFguUmVhZEludmFyaWFudHNRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkSW52YXJpYW50c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi5yZWFkSW52YXJpYW50czIocGFyYW1zKTtcbiAgICB9XG5cbiAgICByZWFkUHJvY2Vzc1N0YXRlKHBhcmFtczogWC5SZWFkUHJvY2Vzc1N0YXRlUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc2VzRG9tYWluLnJlYWRQcm9jZXNzU3RhdGUocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZFByb2Nlc3NTdGF0ZTIocGFyYW1zOiBYLlJlYWRQcm9jZXNzU3RhdGVRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc2VzRG9tYWluLnJlYWRQcm9jZXNzU3RhdGUyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgc2lnblByb2Nlc3MocGFyYW1zOiBYLlNpZ25Qcm9jZXNzUXVlcnkpOiBEYXRhU3RhdGU8WC5TaWduUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi5zaWduUHJvY2VzcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBzaWduUHJvY2VzczIocGFyYW1zOiBYLlNpZ25Qcm9jZXNzUXVlcnkpOiBPYnNlcnZhYmxlPFguU2lnblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4uc2lnblByb2Nlc3MyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgd2F0Y2hDb252ZXJzaW9uU3RhdHVzKHdhaXRlcklkOiBhbnksIHBhcmFtczogWC5XYXRjaENvbnZlcnNpb25TdGF0dXNRdWVyeSk6IERhdGFTdGF0ZTxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi53YXRjaENvbnZlcnNpb25TdGF0dXMod2FpdGVySWQsIHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIHdhdGNoQ29udmVyc2lvblN0YXR1czIod2FpdGVySWQ6IGFueSwgcGFyYW1zOiBYLldhdGNoQ29udmVyc2lvblN0YXR1c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi53YXRjaENvbnZlcnNpb25TdGF0dXMyKHdhaXRlcklkLCBwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFF1aXp6ZXIgRW50aXRpZXMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9xdWl6emVyRG9tYWluOiBYLlF1aXp6ZXJEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBxdWl6emVyRG9tYWluKCk6IFguUXVpenplckRvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcXVpenplckRvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcXVpenplckRvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguUXVpenplckRvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3F1aXp6ZXJEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRRdWl6YXR0ZW1wdHMocXVpeklkOiBhbnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFF1aXphdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucXVpenplckRvbWFpbi5idWxrUmVhZFF1aXphdHRlbXB0cyhxdWl6SWQpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFF1aXphdHRlbXB0czIocXVpeklkOiBhbnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRRdWl6YXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnF1aXp6ZXJEb21haW4uYnVsa1JlYWRRdWl6YXR0ZW1wdHMyKHF1aXpJZCk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRRdWl6emVzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUXVpenplc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucXVpenplckRvbWFpbi5idWxrUmVhZFF1aXp6ZXMoKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRRdWl6emVzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRRdWl6emVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5xdWl6emVyRG9tYWluLmJ1bGtSZWFkUXVpenplczIoKTtcbiAgICB9XG5cbiAgICBjcmVhdGVRdWl6KGJvZHk6IFguQ3JlYXRlUXVpekJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnF1aXp6ZXJEb21haW4uY3JlYXRlUXVpeihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVRdWl6YXR0ZW1wdChxdWl6SWQ6IGFueSwgYm9keTogWC5DcmVhdGVRdWl6YXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUXVpemF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5xdWl6emVyRG9tYWluLmNyZWF0ZVF1aXphdHRlbXB0KHF1aXpJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgZGVsZXRlUXVpeihxdWl6SWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucXVpenplckRvbWFpbi5kZWxldGVRdWl6KHF1aXpJZCk7XG4gICAgfVxuXG4gICAgcmVhZFF1aXoocXVpeklkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnF1aXp6ZXJEb21haW4ucmVhZFF1aXoocXVpeklkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZFF1aXoyKHF1aXpJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucXVpenplckRvbWFpbi5yZWFkUXVpejIocXVpeklkKTtcbiAgICB9XG5cbiAgICB1cGRhdGVRdWl6KHF1aXpJZDogYW55LCBib2R5OiBYLlVwZGF0ZVF1aXpCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5xdWl6emVyRG9tYWluLnVwZGF0ZVF1aXoocXVpeklkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWNhbGwgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9yZWNhbGxEb21haW46IFguUmVjYWxsRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcmVjYWxsRG9tYWluKCk6IFguUmVjYWxsRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9yZWNhbGxEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3JlY2FsbERvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguUmVjYWxsRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fcmVjYWxsRG9tYWluO1xuICAgIH1cblxuICAgIGNyZWF0ZVJlY2FsbFNlc3Npb24oYm9keTogWC5DcmVhdGVSZWNhbGxTZXNzaW9uQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVSZWNhbGxTZXNzaW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucmVjYWxsRG9tYWluLmNyZWF0ZVJlY2FsbFNlc3Npb24oYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZFJlY2FsbFN1bW1hcnkoKTogRGF0YVN0YXRlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5yZWNhbGxEb21haW4ucmVhZFJlY2FsbFN1bW1hcnkoKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZFJlY2FsbFN1bW1hcnkyKCk6IE9ic2VydmFibGU8WC5SZWFkUmVjYWxsU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnJlY2FsbERvbWFpbi5yZWFkUmVjYWxsU3VtbWFyeTIoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTdWJzY3JpcHRpb24gTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9zdWJzY3JpcHRpb25zRG9tYWluOiBYLlN1YnNjcmlwdGlvbnNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBzdWJzY3JpcHRpb25zRG9tYWluKCk6IFguU3Vic2NyaXB0aW9uc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fc3Vic2NyaXB0aW9uc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fc3Vic2NyaXB0aW9uc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguU3Vic2NyaXB0aW9uc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3N1YnNjcmlwdGlvbnNEb21haW47XG4gICAgfVxuXG4gICAgY2hhbmdlU3Vic2NyaXB0aW9uKGJvZHk6IFguQ2hhbmdlU3Vic2NyaXB0aW9uQm9keSk6IE9ic2VydmFibGU8WC5DaGFuZ2VTdWJzY3JpcHRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5zdWJzY3JpcHRpb25zRG9tYWluLmNoYW5nZVN1YnNjcmlwdGlvbihib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBUYXNrcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3Rhc2tzRG9tYWluOiBYLlRhc2tzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgdGFza3NEb21haW4oKTogWC5UYXNrc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fdGFza3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3Rhc2tzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5UYXNrc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3Rhc2tzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkVGFza3MocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnRhc2tzRG9tYWluLmJ1bGtSZWFkVGFza3MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRUYXNrczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy50YXNrc0RvbWFpbi5idWxrUmVhZFRhc2tzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkVGFza0JpbnMocGFyYW1zOiBYLkJ1bGtSZWFkVGFza0JpbnNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnRhc2tzRG9tYWluLmJ1bGtSZWFkVGFza0JpbnMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRUYXNrQmluczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza0JpbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy50YXNrc0RvbWFpbi5idWxrUmVhZFRhc2tCaW5zMihwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFdvcmRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfd29yZHNEb21haW46IFguV29yZHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCB3b3Jkc0RvbWFpbigpOiBYLldvcmRzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl93b3Jkc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fd29yZHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLldvcmRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fd29yZHNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMud29yZHNEb21haW4uYnVsa1JlYWRXb3JkcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRXb3Jkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLndvcmRzRG9tYWluLmJ1bGtSZWFkV29yZHMyKHBhcmFtcyk7XG4gICAgfVxuXG59IiwiICAgICAgICAgICAgICAgIC8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbiAgICAgICAgICAgICAgICBpbXBvcnQgeyBOZ01vZHVsZSwgTW9kdWxlV2l0aFByb3ZpZGVycyB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuICAgICAgICAgICAgICAgIGltcG9ydCB7IEh0dHBDbGllbnRNb2R1bGUgfSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5cbiAgICAgICAgICAgICAgICAvKiogRG9tYWlucyAqL1xuICAgICAgICAgICAgICAgIGltcG9ydCB7IEFjY291bnRTZXR0aW5nc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9hY2NvdW50X3NldHRpbmdzL2luZGV4JztcbmltcG9ydCB7IEFjY291bnRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2FjY291bnRzL2luZGV4JztcbmltcG9ydCB7IEF0dGVtcHRTdGF0c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9hdHRlbXB0X3N0YXRzL2luZGV4JztcbmltcG9ydCB7IEF0dGVtcHRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2F0dGVtcHRzL2luZGV4JztcbmltcG9ydCB7IEF1dGhUb2tlbnNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvYXV0aF90b2tlbnMvaW5kZXgnO1xuaW1wb3J0IHsgQnJpY2tzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2JyaWNrcy9pbmRleCc7XG5pbXBvcnQgeyBDYXJkc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9jYXJkcy9pbmRleCc7XG5pbXBvcnQgeyBDYXRlZ29yaWVzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2NhdGVnb3JpZXMvaW5kZXgnO1xuaW1wb3J0IHsgQ29udGFjdHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvY29udGFjdHMvaW5kZXgnO1xuaW1wb3J0IHsgRG9uYXRpb25zRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2RvbmF0aW9ucy9pbmRleCc7XG5pbXBvcnQgeyBFeHRlcm5hbEFwcHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvZXh0ZXJuYWxfYXBwcy9pbmRleCc7XG5pbXBvcnQgeyBGb2N1c1JlY29yZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvZm9jdXNfcmVjb3Jkcy9pbmRleCc7XG5pbXBvcnQgeyBGcmFnbWVudEhhc2h0YWdzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZyYWdtZW50X2hhc2h0YWdzL2luZGV4JztcbmltcG9ydCB7IEZyYWdtZW50V29yZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvZnJhZ21lbnRfd29yZHMvaW5kZXgnO1xuaW1wb3J0IHsgRnJhZ21lbnRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZyYWdtZW50cy9pbmRleCc7XG5pbXBvcnQgeyBHZW9tZXRyaWVzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2dlb21ldHJpZXMvaW5kZXgnO1xuaW1wb3J0IHsgR29zc2lwRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2dvc3NpcC9pbmRleCc7XG5pbXBvcnQgeyBIYXNodGFnc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9oYXNodGFncy9pbmRleCc7XG5pbXBvcnQgeyBJbnZvaWNlc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9pbnZvaWNlcy9pbmRleCc7XG5pbXBvcnQgeyBMaW5rc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9saW5rcy9pbmRleCc7XG5pbXBvcnQgeyBNZWRpYWl0ZW1zRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL21lZGlhaXRlbXMvaW5kZXgnO1xuaW1wb3J0IHsgTm90aWZpY2F0aW9uc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9ub3RpZmljYXRpb25zL2luZGV4JztcbmltcG9ydCB7IE5vdW5zRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL25vdW5zL2luZGV4JztcbmltcG9ydCB7IFBhdGhzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL3BhdGhzL2luZGV4JztcbmltcG9ydCB7IFBheW1lbnRDYXJkc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9wYXltZW50X2NhcmRzL2luZGV4JztcbmltcG9ydCB7IFBheW1lbnRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL3BheW1lbnRzL2luZGV4JztcbmltcG9ydCB7IFByb2Nlc3Nlc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9wcm9jZXNzZXMvaW5kZXgnO1xuaW1wb3J0IHsgUXVpenplckRvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9xdWl6emVyL2luZGV4JztcbmltcG9ydCB7IFJlY2FsbERvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9yZWNhbGwvaW5kZXgnO1xuaW1wb3J0IHsgU3Vic2NyaXB0aW9uc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9zdWJzY3JpcHRpb25zL2luZGV4JztcbmltcG9ydCB7IFRhc2tzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL3Rhc2tzL2luZGV4JztcbmltcG9ydCB7IFdvcmRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL3dvcmRzL2luZGV4JztcblxuICAgICAgICAgICAgICAgIC8qKiBTZXJ2aWNlcyAqL1xuICAgICAgICAgICAgICAgIGltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbiAgICAgICAgICAgICAgICBpbXBvcnQgeyBBUElTZXJ2aWNlIH0gZnJvbSAnLi9zZXJ2aWNlcy9hcGkuc2VydmljZSc7XG4gICAgICAgICAgICAgICAgaW1wb3J0IHsgQ29uZmlnIH0gZnJvbSAnLi9zZXJ2aWNlcy9jb25maWcuc2VydmljZSc7XG5cbiAgICAgICAgICAgICAgICBATmdNb2R1bGUoe1xuICAgICAgICAgICAgICAgICAgICBpbXBvcnRzOiBbSHR0cENsaWVudE1vZHVsZV0sXG4gICAgICAgICAgICAgICAgICAgIHByb3ZpZGVyczogW1xuICAgICAgICAgICAgICAgICAgICAgICAgQ2xpZW50U2VydmljZSxcblxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gRG9tYWluc1xuICAgICAgICAgICAgICAgICAgICAgICAgQWNjb3VudFNldHRpbmdzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgQWNjb3VudHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBBdHRlbXB0U3RhdHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBBdHRlbXB0c0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEF1dGhUb2tlbnNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBCcmlja3NEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBDYXJkc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIENhdGVnb3JpZXNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBDb250YWN0c0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIERvbmF0aW9uc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEV4dGVybmFsQXBwc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEZvY3VzUmVjb3Jkc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEZyYWdtZW50SGFzaHRhZ3NEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBGcmFnbWVudFdvcmRzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgRnJhZ21lbnRzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgR2VvbWV0cmllc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEdvc3NpcERvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEhhc2h0YWdzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgSW52b2ljZXNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBMaW5rc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIE1lZGlhaXRlbXNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBOb3RpZmljYXRpb25zRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgTm91bnNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBQYXRoc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIFBheW1lbnRDYXJkc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIFBheW1lbnRzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgUHJvY2Vzc2VzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgUXVpenplckRvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIFJlY2FsbERvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIFN1YnNjcmlwdGlvbnNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBUYXNrc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIFdvcmRzRG9tYWluLFxuXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBGYWNhZGVcbiAgICAgICAgICAgICAgICAgICAgICAgIEFQSVNlcnZpY2UsXG4gICAgICAgICAgICAgICAgICAgIF1cbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIGV4cG9ydCBjbGFzcyBDb1NwaGVyZUNsaWVudE1vZHVsZSB7XG4gICAgICAgICAgICAgICAgICAgIHN0YXRpYyBmb3JSb290KGNvbmZpZzogQ29uZmlnKTogTW9kdWxlV2l0aFByb3ZpZGVycyB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5nTW9kdWxlOiBDb1NwaGVyZUNsaWVudE1vZHVsZSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcm92aWRlcnM6IFtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeyBwcm92aWRlOiAnY29uZmlnJywgdXNlVmFsdWU6IGNvbmZpZyB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXVxuICAgICAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0iLCIvKipcbiAqIEdlbmVyYXRlZCBidW5kbGUgaW5kZXguIERvIG5vdCBlZGl0LlxuICovXG5cbmV4cG9ydCAqIGZyb20gJy4vcHVibGljX2FwaSc7XG5cbmV4cG9ydCB7Q29uZmlnIGFzIMOJwrVhfSBmcm9tICcuL3NlcnZpY2VzL2NvbmZpZy5zZXJ2aWNlJzsiXSwibmFtZXMiOlsiXy5oYXMiLCJfLmlzRW1wdHkiLCJYLkFjY291bnRTZXR0aW5nc0RvbWFpbiIsIlguQWNjb3VudHNEb21haW4iLCJYLkF0dGVtcHRTdGF0c0RvbWFpbiIsIlguQXR0ZW1wdHNEb21haW4iLCJYLkF1dGhUb2tlbnNEb21haW4iLCJYLkJyaWNrc0RvbWFpbiIsIlguQ2FyZHNEb21haW4iLCJYLkNhdGVnb3JpZXNEb21haW4iLCJYLkNvbnRhY3RzRG9tYWluIiwiWC5Eb25hdGlvbnNEb21haW4iLCJYLkV4dGVybmFsQXBwc0RvbWFpbiIsIlguRm9jdXNSZWNvcmRzRG9tYWluIiwiWC5GcmFnbWVudEhhc2h0YWdzRG9tYWluIiwiWC5GcmFnbWVudFdvcmRzRG9tYWluIiwiWC5GcmFnbWVudHNEb21haW4iLCJYLkdlb21ldHJpZXNEb21haW4iLCJYLkdvc3NpcERvbWFpbiIsIlguSGFzaHRhZ3NEb21haW4iLCJYLkludm9pY2VzRG9tYWluIiwiWC5MaW5rc0RvbWFpbiIsIlguTWVkaWFpdGVtc0RvbWFpbiIsIlguTm90aWZpY2F0aW9uc0RvbWFpbiIsIlguTm91bnNEb21haW4iLCJYLlBhdGhzRG9tYWluIiwiWC5QYXltZW50Q2FyZHNEb21haW4iLCJYLlBheW1lbnRzRG9tYWluIiwiWC5Qcm9jZXNzZXNEb21haW4iLCJYLlF1aXp6ZXJEb21haW4iLCJYLlJlY2FsbERvbWFpbiIsIlguU3Vic2NyaXB0aW9uc0RvbWFpbiIsIlguVGFza3NEb21haW4iLCJYLldvcmRzRG9tYWluIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0lBbUNFLFlBQXNDLE1BQWMsRUFBVSxJQUFnQjtRQUF4QyxXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQVUsU0FBSSxHQUFKLElBQUksQ0FBWTs7OztRQWQ5RSxVQUFLLEdBQUcsSUFBSSxHQUFHLEVBQXNCLENBQUM7UUFLckIscUJBQWdCLEdBQVcsWUFBWSxDQUFDOzs7Ozs7UUFPeEMsY0FBUyxHQUFHLElBQUksR0FBRyxFQUFFLEdBQUcsRUFBRSxDQUFDO1FBRzFDLElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUM7UUFDbkMsSUFBSSxDQUFDLFNBQVM7WUFDWixJQUFJLENBQUMsTUFBTSxDQUFDLFNBQVMsSUFBSSxJQUFJLENBQUMsZ0JBQWdCLENBQUM7S0FDbEQ7SUFFRCxHQUFHLENBQUksUUFBZ0IsRUFBRSxPQUFpQjtRQUN4QyxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ2xDLE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDakQsT0FBTyxJQUFJLENBQUMsSUFBSTthQUNiLEdBQUcsQ0FBQyxHQUFHLEVBQUUsV0FBVyxDQUFDO2FBQ3JCLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsVUFBVSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsQ0FBa0IsQ0FBQztLQUNsRTtJQUVELElBQUksQ0FBSSxRQUFnQixFQUFFLElBQVMsRUFBRSxPQUFpQjtRQUNwRCxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ2xDLE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDakQsT0FBTyxJQUFJLENBQUMsSUFBSTthQUNiLElBQUksQ0FBQyxHQUFHLEVBQUUsSUFBSSxFQUFFLFdBQVcsQ0FBQzthQUM1QixJQUFJLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLFVBQVUsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQWtCLENBQUM7S0FDbEU7SUFFRCxHQUFHLENBQUksUUFBZ0IsRUFBRSxJQUFTLEVBQUUsT0FBaUI7UUFDbkQsTUFBTSxHQUFHLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQztRQUNsQyxNQUFNLFdBQVcsR0FBRyxJQUFJLENBQUMsY0FBYyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ2pELE9BQU8sSUFBSSxDQUFDLElBQUk7YUFDYixHQUFHLENBQUMsR0FBRyxFQUFFLElBQUksRUFBRSxXQUFXLENBQUM7YUFDM0IsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxVQUFVLENBQUMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxDQUFrQixDQUFDO0tBQ2xFO0lBRUQsTUFBTSxDQUFJLFFBQWdCLEVBQUUsT0FBaUI7UUFDM0MsTUFBTSxHQUFHLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQztRQUNsQyxNQUFNLFdBQVcsR0FBRyxJQUFJLENBQUMsY0FBYyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ2pELE9BQU8sSUFBSSxDQUFDLElBQUk7YUFDYixNQUFNLENBQUMsR0FBRyxFQUFFLFdBQVcsQ0FBQzthQUN4QixJQUFJLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLFVBQVUsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQWtCLENBQUM7S0FDbEU7SUFFRCxZQUFZLENBQUksUUFBZ0IsRUFBRSxPQUFpQjtRQUNqRCxNQUFNLEdBQUcsR0FBRyxPQUFPLElBQUksT0FBTyxDQUFDLE1BQU0sR0FBRyxHQUFHLFFBQVEsSUFBSSxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsRUFBRSxHQUFHLFFBQVEsQ0FBQztRQUNuRyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsRUFBRSxPQUFPLENBQUMsQ0FBQztRQUU3QixJQUFJLEtBQUssR0FBRyxJQUFJLENBQUM7UUFDakIsSUFBSSxNQUEyRCxDQUFDO1FBRWhFLElBQUlBLEdBQUssQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLEVBQUU7WUFDM0IsS0FBSyxHQUFHLE9BQU8sQ0FBQyxLQUFLLENBQUM7U0FDdkI7UUFFRCxJQUFJQSxHQUFLLENBQUMsT0FBTyxFQUFFLFFBQVEsQ0FBQyxFQUFFO1lBQzVCLE1BQU0sR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDO1NBQ3pCOztRQUdELE1BQU0sS0FBSyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDOztRQUdsQyxJQUFJLEtBQUssQ0FBQyxZQUFZLENBQUMsT0FBTyw0QkFBNEI7WUFDeEQsT0FBTyxLQUFLLENBQUMsU0FBUyxDQUFDO1NBQ3hCO1FBRUQsTUFBTSxXQUFXLEdBQUcsQ0FBQyxJQUFJLElBQUksRUFBRSxDQUFDO1FBQ2hDLElBQ0UsV0FBVyxHQUFHLEtBQUssQ0FBQyxZQUFZLENBQUMsUUFBUSxHQUFHLElBQUksQ0FBQyxTQUFTOztZQUUxRCxDQUFDLEtBQ0gsRUFBRTtZQUNBLEtBQUssQ0FBQyxZQUFZLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQztZQUNsQyxJQUFJLENBQUMsR0FBRyxDQUFDLFFBQVEsRUFBRSxPQUFPLENBQUM7aUJBQ3hCLElBQUksQ0FDSCxHQUFHLENBQUMsSUFBSSxLQUFLLE9BQU8sQ0FBQyxXQUFXLEdBQUcsSUFBSSxDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUN0RTtpQkFDQSxTQUFTLENBQ1IsSUFBSTtnQkFDRixLQUFLLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUM7Z0JBQ2pDLEtBQUssQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDQyxPQUFTLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQztnQkFDL0MsS0FBSyxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO2dCQUNyQyxLQUFLLENBQUMsWUFBWSxDQUFDLE9BQU8sR0FBRyxLQUFLLENBQUM7Z0JBQ25DLEtBQUssQ0FBQyxZQUFZLENBQUMsUUFBUSxHQUFHLFdBQVcsQ0FBQzthQUMzQyxFQUNELEdBQUc7Z0JBQ0QsS0FBSyxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO2dCQUNwQyxLQUFLLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLENBQUM7Z0JBQ2xDLEtBQUssQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztnQkFDckMsS0FBSyxDQUFDLFlBQVksQ0FBQyxPQUFPLEdBQUcsS0FBSyxDQUFDO2FBQ3BDLENBQ0YsQ0FBQztTQUNMO2FBQU07WUFDTCxLQUFLLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7U0FDdEM7UUFFRCxPQUFPLEtBQUssQ0FBQyxTQUFTLENBQUM7S0FDeEI7SUFFTyxTQUFTLENBQUMsR0FBVyxFQUFFLE9BQWlCO1FBQzlDLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsRUFBRTtZQUN4QixJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUU7Z0JBQ2xCLFNBQVMsRUFBRTtvQkFDVCxRQUFRLEVBQUUsSUFBSSxlQUFlLENBQUMsSUFBSSxDQUFDO29CQUNuQyxPQUFPLEVBQUUsSUFBSSxlQUFlLENBQUMsS0FBSyxDQUFDO29CQUNuQyxLQUFLLEVBQUUsSUFBSSxlQUFlLENBQUMsSUFBSSxDQUFDO2lCQUNqQztnQkFDRCxZQUFZLEVBQUU7b0JBQ1osUUFBUSxFQUFFLENBQUM7b0JBQ1gsT0FBTyxFQUFFLEtBQUs7aUJBQ2Y7YUFDRixDQUFDLENBQUM7U0FDSjthQUFNO1lBQ0wsSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUM7U0FDbkQ7S0FDRjtJQUVPLGNBQWMsQ0FDcEIsT0FBaUI7UUFNakIsTUFBTSxxQkFBcUIsR0FBR0QsR0FBSyxDQUFDLE9BQU8sRUFBRSx1QkFBdUIsQ0FBQztjQUNqRSxPQUFPLENBQUMscUJBQXFCO2NBQzdCLElBQUksQ0FBQztRQUNULE1BQU0sSUFBSSxHQUFHLENBQUMsT0FBTyxJQUFJLE9BQU8sQ0FBQyxJQUFJLEtBQUssU0FBUyxDQUFDO1FBRXBELElBQUksV0FBVyxHQUlYO1lBQ0YsT0FBTyxFQUFFLElBQUksQ0FBQyxVQUFVLENBQUMscUJBQXFCLEVBQUUsSUFBSSxDQUFDO1NBQ3RELENBQUM7UUFFRixJQUFJQSxHQUFLLENBQUMsT0FBTyxFQUFFLFNBQVMsQ0FBQyxFQUFFOztZQUU3QixLQUFLLElBQUksR0FBRyxJQUFJLE9BQU8sQ0FBQyxPQUFPLEVBQUU7Z0JBQy9CLFdBQVcsQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQVMsT0FBUSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQzthQUN4RDs7U0FFRjtRQUVELElBQUlBLEdBQUssQ0FBQyxPQUFPLEVBQUUsUUFBUSxDQUFDLEVBQUU7WUFDNUIsV0FBVyxDQUFDLE1BQU0sR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDO1NBQ3JDO1FBRUQsSUFBSUEsR0FBSyxDQUFDLE9BQU8sRUFBRSxnQkFBZ0IsQ0FBQyxFQUFFO1lBQ3BDLFdBQVcsQ0FBQyxjQUFjLEdBQUcsT0FBTyxDQUFDLGNBQWMsQ0FBQztTQUNyRDtRQUVELE9BQU8sV0FBVyxDQUFDO0tBQ3BCO0lBRU8sVUFBVSxDQUNoQixxQkFBOEIsRUFDOUIsSUFBYTtRQUViLElBQUksT0FBTyxHQUFHO1lBQ1osY0FBYyxFQUFFLGtCQUFrQjtTQUNuQyxDQUFDO1FBRUYsSUFBSSxxQkFBcUIsRUFBRTtZQUN6QixPQUFPLENBQUMsZUFBZSxDQUFDLEdBQUcsVUFBVSxJQUFJLENBQUMsUUFBUSxFQUFFLEVBQUUsQ0FBQztTQUN4RDtRQUVELElBQUksSUFBSSxFQUFFO1lBQ1IsT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLElBQUksQ0FBQztTQUN4QjtRQUVELE9BQU8sT0FBTyxDQUFDO0tBQ2hCO0lBRU8sTUFBTSxDQUFDLFFBQWdCO1FBQzdCLE9BQU8sR0FBRyxJQUFJLENBQUMsT0FBTyxHQUFHLFFBQVEsRUFBRSxDQUFDO0tBQ3JDO0lBRU8sUUFBUTtRQUNkLE9BQU8sWUFBWSxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUM7S0FDN0M7SUFFTyxXQUFXLENBQUMsS0FBd0I7UUFDMUMsSUFBSSxLQUFLLENBQUMsS0FBSyxZQUFZLFVBQVUsRUFBRTs7WUFFckMsT0FBTyxDQUFDLEtBQUssQ0FBQyxvQkFBb0IsRUFBRSxLQUFLLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1NBQzFEO2FBQU07OztZQUdMLE9BQU8sQ0FBQyxLQUFLLENBQ1gseUJBQXlCLEtBQUssQ0FBQyxNQUFNLElBQUksR0FBRyxhQUFhLEtBQUssQ0FBQyxLQUFLLEVBQUUsQ0FDdkUsQ0FBQztTQUNIOztRQUdELE9BQU8sVUFBVSxDQUFDLGlEQUFpRCxDQUFDLENBQUM7S0FDdEU7OztZQXJORixVQUFVLFNBQUM7Z0JBQ1YsVUFBVSxFQUFFLE1BQU07YUFDbkI7Ozs7NENBbUJjLE1BQU0sU0FBQyxRQUFRO1lBakM1QixVQUFVOzs7O0FDRlo7Ozs7QUFLQTtJQWVJLFlBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7S0FBSTs7OztJQUt0QyxrQkFBa0I7UUFDckIsT0FBTyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBK0Isb0JBQW9CLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0tBQ3hIO0lBRU0sbUJBQW1CO1FBQ3RCLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQStCLG9CQUFvQixFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztLQUMvRzs7OztJQUtNLG9CQUFvQixDQUFDLElBQWdDO1FBQ3hELE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixHQUFHLENBQWlDLG9CQUFvQixFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDO2FBQ2hHLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUNDLE9BQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDekM7OztZQXRCSixVQUFVOzs7O1lBTEYsYUFBYTs7O0FDYnRCOzs7O0FBS0E7SUFlSSxZQUFvQixNQUFxQjtRQUFyQixXQUFNLEdBQU4sTUFBTSxDQUFlO0tBQUk7Ozs7Ozs7SUFRdEMsZUFBZSxDQUFDLElBQTJCO1FBQzlDLE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQTRCLGlCQUFpQixFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLEtBQUssRUFBRSxDQUFDO2FBQzFGLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUNBLE9BQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDekM7Ozs7Ozs7SUFRTSxnQkFBZ0IsQ0FBQyxNQUErQjtRQUNuRCxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFxQyxpQkFBaUIsRUFBRSxFQUFFLE1BQU0sRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDeEo7SUFFTSxpQkFBaUIsQ0FBQyxNQUErQjtRQUNwRCxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFxQyxpQkFBaUIsRUFBRSxFQUFFLE1BQU0sRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDL0k7Ozs7Ozs7SUFRTSxjQUFjLENBQUMsSUFBMEI7UUFDNUMsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBMkIsd0JBQXdCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDL0YsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7Ozs7OztJQVFNLGFBQWEsQ0FBQyxJQUF5QjtRQUMxQyxPQUFPLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUEwQixpQkFBaUIsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQzthQUN4RixJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7Ozs7O0lBUU0sV0FBVztRQUNkLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQXdCLG9CQUFvQixFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztLQUNqSDtJQUVNLFlBQVk7UUFDZixPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUF3QixvQkFBb0IsRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDeEc7Ozs7Ozs7SUFRTSxhQUFhLENBQUMsSUFBeUI7UUFDMUMsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBMEIsdUJBQXVCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUM7YUFDOUYsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7Ozs7OztJQVFNLDBCQUEwQixDQUFDLElBQXNDO1FBQ3BFLE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQXVDLDhCQUE4QixFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLEtBQUssRUFBRSxDQUFDO2FBQ2xILElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUNBLE9BQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDekM7Ozs7Ozs7SUFRTSxzQkFBc0IsQ0FBQyxJQUFrQztRQUM1RCxPQUFPLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUFtQyxrQ0FBa0MsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQzthQUNsSCxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7Ozs7O0lBUU0sYUFBYSxDQUFDLElBQXlCO1FBQzFDLE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixHQUFHLENBQTBCLG9CQUFvQixFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDO2FBQ3pGLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUNBLE9BQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDekM7OztZQWxISixVQUFVOzs7O1lBTEYsYUFBYTs7O0FDYnRCOzs7Ozs7O0FBb0NBLElBQVksNkJBTVg7QUFORCxXQUFZLDZCQUE2QjtJQUNyQyxnREFBZSxDQUFBO0lBQ2YsOENBQWEsQ0FBQTtJQUNiLG9EQUFtQixDQUFBO0lBQ25CLGtEQUFpQixDQUFBO0lBQ2pCLG9EQUFtQixDQUFBO0NBQ3RCLEVBTlcsNkJBQTZCLEtBQTdCLDZCQUE2QixRQU14Qzs7OztBQWlERCxJQUFZLHdCQU1YO0FBTkQsV0FBWSx3QkFBd0I7SUFDaEMsMkNBQWUsQ0FBQTtJQUNmLHlDQUFhLENBQUE7SUFDYiwrQ0FBbUIsQ0FBQTtJQUNuQiw2Q0FBaUIsQ0FBQTtJQUNqQiwrQ0FBbUIsQ0FBQTtDQUN0QixFQU5XLHdCQUF3QixLQUF4Qix3QkFBd0IsUUFNbkM7Ozs7QUF1RUQsSUFBWSwwQkFNWDtBQU5ELFdBQVksMEJBQTBCO0lBQ2xDLDZDQUFlLENBQUE7SUFDZiwyQ0FBYSxDQUFBO0lBQ2IsaURBQW1CLENBQUE7SUFDbkIsK0NBQWlCLENBQUE7SUFDakIsaURBQW1CLENBQUE7Q0FDdEIsRUFOVywwQkFBMEIsS0FBMUIsMEJBQTBCLFFBTXJDOztBQzlLRDs7OztBQUtBO0lBZUksWUFBb0IsTUFBcUI7UUFBckIsV0FBTSxHQUFOLE1BQU0sQ0FBZTtLQUFJOzs7Ozs7O0lBUXRDLG9CQUFvQixDQUFDLE1BQW1DO1FBQzNELE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQWlDLHdCQUF3QixFQUFFLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDdEk7SUFFTSxxQkFBcUIsQ0FBQyxNQUFtQztRQUM1RCxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFpQyx3QkFBd0IsRUFBRSxFQUFFLE1BQU0sRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0tBQzdIOzs7Ozs7O0lBUU0saUJBQWlCLENBQUMsSUFBNkI7UUFDbEQsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBOEIsd0JBQXdCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDbEcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7Ozs7OztJQVFNLHlCQUF5QixDQUFDLElBQXFDO1FBQ2xFLE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQXNDLGlDQUFpQyxFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDO2FBQ25ILElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUNBLE9BQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDekM7OztZQXhDSixVQUFVOzs7O1lBTEYsYUFBYTs7O0FDYnRCOzs7O0FBS0E7SUFlSSxZQUFvQixNQUFxQjtRQUFyQixXQUFNLEdBQU4sTUFBTSxDQUFlO0tBQUk7Ozs7Ozs7SUFRdEMsdUJBQXVCLENBQUMsTUFBVztRQUN0QyxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUE0Qyw0QkFBNEIsTUFBTSxFQUFFLEVBQUUsRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDMUs7SUFFTSx3QkFBd0IsQ0FBQyxNQUFXO1FBQ3ZDLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQTRDLDRCQUE0QixNQUFNLEVBQUUsRUFBRSxFQUFFLFdBQVcsRUFBRSxNQUFNLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztLQUNqSzs7Ozs7OztJQVFNLGFBQWEsQ0FBQyxJQUF5QjtRQUMxQyxPQUFPLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUEwQixtQkFBbUIsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUN6RixJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7Ozs7O0lBUU0sYUFBYSxDQUFDLFNBQWMsRUFBRSxJQUF5QjtRQUMxRCxPQUFPLElBQUksQ0FBQyxNQUFNO2FBQ2IsR0FBRyxDQUEwQixvQkFBb0IsU0FBUyxFQUFFLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDcEcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7O1lBeENKLFVBQVU7Ozs7WUFMRixhQUFhOzs7QUNidEI7Ozs7QUFLQTtJQWVJLFlBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7S0FBSTs7Ozs7OztJQVF0QyxrQkFBa0I7UUFDckIsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBK0IsOEJBQThCLEVBQUUsRUFBRSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUM7YUFDeEcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7Ozs7OztJQVFNLGVBQWUsQ0FBQyxJQUEyQjtRQUM5QyxPQUFPLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUE0QixvQkFBb0IsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQzthQUM3RixJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7O0lBS00sNEJBQTRCLENBQUMsSUFBd0M7UUFDeEUsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBeUMsNkJBQTZCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUM7YUFDbkgsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7OztJQUtNLGtDQUFrQyxDQUFDLElBQThDO1FBQ3BGLE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQStDLG9DQUFvQyxFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLEtBQUssRUFBRSxDQUFDO2FBQ2hJLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUNBLE9BQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDekM7Ozs7SUFLTSwwQkFBMEIsQ0FBQyxJQUFzQztRQUNwRSxPQUFPLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUF1QywyQkFBMkIsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQzthQUMvRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7O0lBS00sZ0NBQWdDLENBQUMsSUFBNEM7UUFDaEYsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBNkMsa0NBQWtDLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUM7YUFDNUgsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7Ozs7OztJQVFNLGVBQWU7UUFDbEIsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLEdBQUcsQ0FBNEIsb0JBQW9CLEVBQUUsRUFBRSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDekYsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7O1lBMUVKLFVBQVU7Ozs7WUFMRixhQUFhOzs7QUNidEI7Ozs7QUFLQTtJQWVJLFlBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7S0FBSTs7OztJQUt0QyxvQkFBb0IsQ0FBQyxNQUFXO1FBQ25DLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQXlDLFVBQVUsTUFBTSxZQUFZLEVBQUUsRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDL0o7SUFFTSxxQkFBcUIsQ0FBQyxNQUFXO1FBQ3BDLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQXlDLFVBQVUsTUFBTSxZQUFZLEVBQUUsRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDdEo7Ozs7SUFLTSxhQUFhO1FBQ2hCLE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQWtDLFNBQVMsRUFBRSxFQUFFLFdBQVcsRUFBRSxNQUFNLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztLQUNySTtJQUVNLGNBQWM7UUFDakIsT0FBTyxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBa0MsU0FBUyxFQUFFLEVBQUUsV0FBVyxFQUFFLE1BQU0sRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0tBQzVIOzs7O0lBS00sVUFBVSxDQUFDLElBQXNCO1FBQ3BDLE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQXVCLFNBQVMsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUM1RSxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7O0lBS00saUJBQWlCLENBQUMsTUFBVyxFQUFFLElBQTZCO1FBQy9ELE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQThCLFVBQVUsTUFBTSxZQUFZLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDdEcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQ0EsT0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztLQUN6Qzs7OztJQUtNLFVBQVUsQ0FBQyxNQUFXO1FBQ3pCLE9BQU8sSUFBSSxDQUFDLE1BQU07YUFDYixNQUFNLENBQXVCLFVBQVUsTUFBTSxFQUFFLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUNqRixJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7O0lBS00sUUFBUSxDQUFDLE1BQVc7UUFDdkIsT0FBTyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBcUIsVUFBVSxNQUFNLEVBQUUsRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7S0FDNUc7SUFFTSxTQUFTLENBQUMsTUFBVztRQUN4QixPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFxQixVQUFVLE1BQU0sRUFBRSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztLQUNuRzs7OztJQUtNLFVBQVUsQ0FBQyxNQUFXLEVBQUUsSUFBc0I7UUFDakQsT0FBTyxJQUFJLENBQUMsTUFBTTthQUNiLEdBQUcsQ0FBdUIsVUFBVSxNQUFNLEVBQUUsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUNwRixJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDQSxPQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDOzs7WUF2RUosVUFBVTs7OztZQUxGLGFBQWE7OztBQ2J0Qjs7Ozs7OztBQWdEQSxJQUFZLDJCQW1CWDtBQW5CRCxXQUFZLDJCQUEyQjtJQUNuQyx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7Q0FDWixFQW5CVywyQkFBMkIsS0FBM0IsMkJBQTJCLFFBbUJ0QztBQUVELElBQVksc0JBa0dYO0FBbEdELFdBQVksc0JBQXNCO0lBQzlCLG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7Q0FDWixFQWxHVyxzQkFBc0IsS0FBdEIsc0JBQXNCLFFBa0dqQzs7OztBQTRGRCxJQUFZLDJCQW1CWDtBQW5CRCxXQUFZLDJCQUEyQjtJQUNuQyx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7SUFDVCx3Q0FBUyxDQUFBO0lBQ1Qsd0NBQVMsQ0FBQTtJQUNULHdDQUFTLENBQUE7Q0FDWixFQW5CVywyQkFBMkIsS0FBM0IsMkJBQTJCLFFBbUJ0QztBQUVELElBQVksc0JBa0dYO0FBbEdELFdBQVksc0JBQXNCO0lBQzlCLG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FBQTtJQUNULG1DQUFTLENBQUE7SUFDVCxtQ0FBUyxDQUFBO0lBQ1QsbUNBQVMsQ0FB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