(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('@angular/core'), require('@angular/common/http'), require('rxjs'), require('rxjs/operators'), require('underscore')) :
    typeof define === 'function' && define.amd ? define('@cosphere/client', ['exports', '@angular/core', '@angular/common/http', 'rxjs', 'rxjs/operators', 'underscore'], factory) :
    (factory((global.cosphere = global.cosphere || {}, global.cosphere.client = {}),global.ng.core,global.ng.common.http,global.rxjs,global.rxjs.operators,global._));
}(this, (function (exports,i0,i1,rxjs,operators,_) { 'use strict';

    var ClientService = (function () {
        function ClientService(config, http) {
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
        ClientService.prototype.get = function (endpoint, options) {
            var url = this.getUrl(endpoint);
            var httpOptions = this.getHttpOptions(options);
            return this.http
                .get(url, httpOptions)
                .pipe(operators.retry(3), operators.catchError(this.handleError));
        };
        ClientService.prototype.post = function (endpoint, body, options) {
            var url = this.getUrl(endpoint);
            var httpOptions = this.getHttpOptions(options);
            return this.http
                .post(url, body, httpOptions)
                .pipe(operators.retry(3), operators.catchError(this.handleError));
        };
        ClientService.prototype.put = function (endpoint, body, options) {
            var url = this.getUrl(endpoint);
            var httpOptions = this.getHttpOptions(options);
            return this.http
                .put(url, body, httpOptions)
                .pipe(operators.retry(3), operators.catchError(this.handleError));
        };
        ClientService.prototype.delete = function (endpoint, options) {
            var url = this.getUrl(endpoint);
            var httpOptions = this.getHttpOptions(options);
            return this.http
                .delete(url, httpOptions)
                .pipe(operators.retry(3), operators.catchError(this.handleError));
        };
        ClientService.prototype.getDataState = function (endpoint, options) {
            var key = options && options.params ? endpoint + "_" + JSON.stringify(options.params) : endpoint;
            this.initState(key, options);
            var cache = true;
            var params;
            if (_.has(options, 'cache')) {
                cache = options.cache;
            }
            if (_.has(options, 'params')) {
                params = options.params;
            }
            // Get the endpoint state
            var state = this.state.get(key);
            // Do not allow invoke the same GET request while one is pending
            if (state.requestState.pending /*&& !_.isEmpty(params)*/) {
                return state.dataState;
            }
            var currentTime = +new Date();
            if (currentTime - state.requestState.cachedAt > this.cacheTime ||
                // !_.isEmpty(params) ||
                !cache) {
                state.requestState.pending = true;
                this.get(endpoint, options)
                    .pipe(operators.map(function (data) { return (options.responseMap ? data[options.responseMap] : data); }))
                    .subscribe(function (data) {
                    state.dataState.data$.next(data);
                    state.dataState.isData$.next(!_.isEmpty(data));
                    state.dataState.loading$.next(false);
                    state.requestState.pending = false;
                    state.requestState.cachedAt = currentTime;
                }, function (err) {
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
        };
        ClientService.prototype.initState = function (key, options) {
            if (!this.state.has(key)) {
                this.state.set(key, {
                    dataState: {
                        loading$: new rxjs.BehaviorSubject(true),
                        isData$: new rxjs.BehaviorSubject(false),
                        data$: new rxjs.BehaviorSubject(null)
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
        };
        ClientService.prototype.getHttpOptions = function (options) {
            var authorizationRequired = _.has(options, 'authorizationRequired')
                ? options.authorizationRequired
                : true;
            var etag = (options && options.etag) || undefined;
            var httpOptions = {
                headers: this.getHeaders(authorizationRequired, etag)
            };
            if (_.has(options, 'headers')) {
                // tslint:disable
                for (var key in options.headers) {
                    httpOptions.headers[key] = options.headers[key];
                }
                // tslint:enable
            }
            if (_.has(options, 'params')) {
                httpOptions.params = options.params;
            }
            if (_.has(options, 'reportProgress')) {
                httpOptions.reportProgress = options.reportProgress;
            }
            return httpOptions;
        };
        ClientService.prototype.getHeaders = function (authorizationRequired, etag) {
            var headers = {
                'Content-Type': 'application/json'
            };
            if (authorizationRequired) {
                headers['Authorization'] = "Bearer " + this.getToken();
            }
            if (etag) {
                headers['ETag'] = etag;
            }
            return headers;
        };
        ClientService.prototype.getUrl = function (endpoint) {
            return "" + this.baseUrl + endpoint;
        };
        ClientService.prototype.getToken = function () {
            return localStorage.getItem(this.authToken);
        };
        ClientService.prototype.handleError = function (error) {
            if (error.error instanceof ErrorEvent) {
                // A client-side or network error occurred. Handle it accordingly.
                console.error('An error occurred:', error.error.message);
            }
            else {
                // The backend returned an unsuccessful response code.
                // The response body may contain clues as to what went wrong,
                console.error("Backend returned code " + error.status + ", " + ("body was: " + error.error));
            }
            // return an observable with a user-facing error message
            return rxjs.throwError('Something bad happened; please try again later.');
        };
        ClientService.decorators = [
            { type: i0.Injectable, args: [{
                        providedIn: 'root'
                    },] }
        ];
        /** @nocollapse */
        ClientService.ctorParameters = function () {
            return [
                { type: undefined, decorators: [{ type: i0.Inject, args: ['config',] }] },
                { type: i1.HttpClient }
            ];
        };
        ClientService.ngInjectableDef = i0.defineInjectable({ factory: function ClientService_Factory() { return new ClientService(i0.inject("config"), i0.inject(i1.HttpClient)); }, token: ClientService, providedIn: "root" });
        return ClientService;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var AccountSettingsDomain = (function () {
        function AccountSettingsDomain(client) {
            this.client = client;
        }
        /**
         * Read Account Settings
         */
        AccountSettingsDomain.prototype.readAccountsetting = function () {
            return this.client.getDataState('/account/settings/', { authorizationRequired: true });
        };
        AccountSettingsDomain.prototype.readAccountsetting2 = function () {
            return this.client.get('/account/settings/', { authorizationRequired: true });
        };
        /**
         * Update Account Settings
         */
        AccountSettingsDomain.prototype.updateAccountsetting = function (body) {
            return this.client
                .put('/account/settings/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        AccountSettingsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        AccountSettingsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return AccountSettingsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var AccountsDomain = (function () {
        function AccountsDomain(client) {
            this.client = client;
        }
        /**
         * Activate Account
         * -------------
         *
         * Activate Account by decoding the `code` which contains the confirmation off the intent and was signed by the user itself.
         */
        AccountsDomain.prototype.activateAccount = function (body) {
            return this.client
                .post('/auth/activate/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Bulk Read Mentors' Account
         * -------------
         *
         * Enable one to Read all available Mentor accounts
         */
        AccountsDomain.prototype.bulkReadAccounts = function (params) {
            return this.client.getDataState('/auth/accounts/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        AccountsDomain.prototype.bulkReadAccounts2 = function (params) {
            return this.client.get('/auth/accounts/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Change Password
         * -------------
         *
         * Enables one to change one's password for an authenticated user.
         */
        AccountsDomain.prototype.changePassword = function (body) {
            return this.client
                .post('/auth/change_password/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Account
         * -------------
         *
         * Creates User and Account if provided data are valid.
         */
        AccountsDomain.prototype.createAccount = function (body) {
            return this.client
                .post('/auth/accounts/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read My Account
         * -------------
         *
         * Read my Account data.
         */
        AccountsDomain.prototype.readAccount = function () {
            return this.client.getDataState('/auth/accounts/me/', { authorizationRequired: true });
        };
        AccountsDomain.prototype.readAccount2 = function () {
            return this.client.get('/auth/accounts/me/', { authorizationRequired: true });
        };
        /**
         * Reset Password
         * -------------
         *
         * Enables one to reset her password in case the old one cannot be recalled.
         */
        AccountsDomain.prototype.resetPassword = function (body) {
            return this.client
                .post('/auth/reset_password/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Send Account Activation Email
         * -------------
         *
         * Send an Email containing the confirmation link which when clicked kicks of the Account Activation. Even though the activation email is send automatically during the Sign Up phase one should have a way to send it again in case it was not delivered.
         */
        AccountsDomain.prototype.sendAccountActivationEmail = function (body) {
            return this.client
                .post('/auth/send_activation_email/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Send Reset Password Email
         * -------------
         *
         * Send an Email containing the confirmation link which when clicked kicks of the real Reset Password operation.
         */
        AccountsDomain.prototype.sendResetPasswordEmail = function (body) {
            return this.client
                .post('/auth/send_reset_password_email/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Update My Account
         * -------------
         *
         * Update my Account data.
         */
        AccountsDomain.prototype.updateAccount = function (body) {
            return this.client
                .put('/auth/accounts/me/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        AccountsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        AccountsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return AccountsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (BulkReadAccountsResponseAtype) {
        BulkReadAccountsResponseAtype["ADMIN"] = "ADMIN";
        BulkReadAccountsResponseAtype["FREE"] = "FREE";
        BulkReadAccountsResponseAtype["LEARNER"] = "LEARNER";
        BulkReadAccountsResponseAtype["MENTOR"] = "MENTOR";
        BulkReadAccountsResponseAtype["PARTNER"] = "PARTNER";
    })(exports.BulkReadAccountsResponseAtype || (exports.BulkReadAccountsResponseAtype = {}));
    (function (ReadAccountResponseAtype) {
        ReadAccountResponseAtype["ADMIN"] = "ADMIN";
        ReadAccountResponseAtype["FREE"] = "FREE";
        ReadAccountResponseAtype["LEARNER"] = "LEARNER";
        ReadAccountResponseAtype["MENTOR"] = "MENTOR";
        ReadAccountResponseAtype["PARTNER"] = "PARTNER";
    })(exports.ReadAccountResponseAtype || (exports.ReadAccountResponseAtype = {}));
    (function (UpdateAccountResponseAtype) {
        UpdateAccountResponseAtype["ADMIN"] = "ADMIN";
        UpdateAccountResponseAtype["FREE"] = "FREE";
        UpdateAccountResponseAtype["LEARNER"] = "LEARNER";
        UpdateAccountResponseAtype["MENTOR"] = "MENTOR";
        UpdateAccountResponseAtype["PARTNER"] = "PARTNER";
    })(exports.UpdateAccountResponseAtype || (exports.UpdateAccountResponseAtype = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var AttemptStatsDomain = (function () {
        function AttemptStatsDomain(client) {
            this.client = client;
        }
        /**
         * List Attempt Stats
         * -------------
         *
         * List Attempt Stats by filtering existing ones.
         */
        AttemptStatsDomain.prototype.bulkReadAttemptstats = function (params) {
            return this.client.getDataState('/recall/attempt_stats/', { params: params, authorizationRequired: true });
        };
        AttemptStatsDomain.prototype.bulkReadAttemptstats2 = function (params) {
            return this.client.get('/recall/attempt_stats/', { params: params, authorizationRequired: true });
        };
        /**
         * Create Attempt Stat
         * -------------
         *
         * Create Attempt Stat which stores information about basis statistics of a particular recall attempt.
         */
        AttemptStatsDomain.prototype.createAttemptstat = function (body) {
            return this.client
                .post('/recall/attempt_stats/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create External Attempt Stat
         * -------------
         *
         * Create External Attempt Stat meaning one which was rendered elsewhere in any of the multiple CoSphere apps.
         */
        AttemptStatsDomain.prototype.createExternalAttemptStat = function (body) {
            return this.client
                .post('/recall/attempt_stats/external/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        AttemptStatsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        AttemptStatsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return AttemptStatsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var AttemptsDomain = (function () {
        function AttemptsDomain(client) {
            this.client = client;
        }
        /**
         * List Attempts By Card
         * -------------
         *
         * List Attempts for a specific Card given by its Id.
         */
        AttemptsDomain.prototype.bulkReadAttemptsByCards = function (cardId) {
            return this.client.getDataState("/recall/attempts/by_card/" + cardId, { responseMap: 'data', authorizationRequired: true });
        };
        AttemptsDomain.prototype.bulkReadAttemptsByCards2 = function (cardId) {
            return this.client.get("/recall/attempts/by_card/" + cardId, { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Create Attempt
         * -------------
         *
         * Create Attempt which is a reflection of someone's knowledge regarding a given Card.
         */
        AttemptsDomain.prototype.createAttempt = function (body) {
            return this.client
                .post('/recall/attempts/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Update Attempt
         * -------------
         *
         * Update existing Attempt with new cells and / or style.
         */
        AttemptsDomain.prototype.updateAttempt = function (attemptId, body) {
            return this.client
                .put("/recall/attempts/" + attemptId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        AttemptsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        AttemptsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return AttemptsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var AuthTokensDomain = (function () {
        function AuthTokensDomain(client) {
            this.client = client;
        }
        /**
         * Authorize a given token
         * -------------
         *
         * Can be called by the API Gateway in order to authorize every request using provided token.
         */
        AuthTokensDomain.prototype.authorizeAuthToken = function () {
            return this.client
                .post('/auth/auth_tokens/authorize/', {}, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Sign In
         * -------------
         *
         * Validates data provided on the input and if successful returns auth token.
         */
        AuthTokensDomain.prototype.createAuthToken = function (body) {
            return this.client
                .post('/auth/auth_tokens/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Facebook Auth Token
         */
        AuthTokensDomain.prototype.createFacebookBasedAuthToken = function (body) {
            return this.client
                .post('/auth/auth_tokens/facebook/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Mobile Facebook Auth Token
         */
        AuthTokensDomain.prototype.createFacebookBasedMobileAuthToken = function (body) {
            return this.client
                .post('/auth/auth_tokens/facebook/mobile/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Google Auth Token
         */
        AuthTokensDomain.prototype.createGoogleBasedAuthToken = function (body) {
            return this.client
                .post('/auth/auth_tokens/google/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Mobile Google Auth Token
         */
        AuthTokensDomain.prototype.createGoogleBasedMobileAuthToken = function (body) {
            return this.client
                .post('/auth/auth_tokens/google/mobile/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Refresh JWT token
         * -------------
         *
         * Should be used whenever token is close to expiry or if one is requested to refresh the token because for example account type was changed and new token should be requested to reflect that change.
         */
        AuthTokensDomain.prototype.updateAuthToken = function () {
            return this.client
                .put('/auth/auth_tokens/', {}, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        AuthTokensDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        AuthTokensDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return AuthTokensDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var BricksDomain = (function () {
        function BricksDomain(client) {
            this.client = client;
        }
        /**
         * Bulk Read Bricks Game Attempts
         */
        BricksDomain.prototype.bulkReadGameattempts = function (gameId) {
            return this.client.getDataState("/games/" + gameId + "/attempts/", { responseMap: 'data', authorizationRequired: true });
        };
        BricksDomain.prototype.bulkReadGameattempts2 = function (gameId) {
            return this.client.get("/games/" + gameId + "/attempts/", { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Bulk Read Game
         */
        BricksDomain.prototype.bulkReadGames = function () {
            return this.client.getDataState('/games/', { responseMap: 'data', authorizationRequired: true });
        };
        BricksDomain.prototype.bulkReadGames2 = function () {
            return this.client.get('/games/', { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Create Game
         */
        BricksDomain.prototype.createGame = function (body) {
            return this.client
                .post('/games/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Bricks Game Attempt
         */
        BricksDomain.prototype.createGameattempt = function (gameId, body) {
            return this.client
                .post("/games/" + gameId + "/attempts/", body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Delete Game
         */
        BricksDomain.prototype.deleteGame = function (gameId) {
            return this.client
                .delete("/games/" + gameId, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Game
         */
        BricksDomain.prototype.readGame = function (gameId) {
            return this.client.getDataState("/games/" + gameId, { authorizationRequired: true });
        };
        BricksDomain.prototype.readGame2 = function (gameId) {
            return this.client.get("/games/" + gameId, { authorizationRequired: true });
        };
        /**
         * Update Game
         */
        BricksDomain.prototype.updateGame = function (gameId, body) {
            return this.client
                .put("/games/" + gameId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        BricksDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        BricksDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return BricksDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
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
    })(exports.CreateGameBodyAudioLanguage || (exports.CreateGameBodyAudioLanguage = {}));
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
    })(exports.CreateGameBodyLanguage || (exports.CreateGameBodyLanguage = {}));
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
    })(exports.UpdateGameBodyAudioLanguage || (exports.UpdateGameBodyAudioLanguage = {}));
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
    })(exports.UpdateGameBodyLanguage || (exports.UpdateGameBodyLanguage = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var CardsDomain = (function () {
        function CardsDomain(client) {
            this.client = client;
        }
        /**
         * Remove Card
         * -------------
         *
         * Remove list of Cards specified by their ids.
         */
        CardsDomain.prototype.bulkDeleteCards = function (params) {
            return this.client
                .delete('/cards/', { params: params, authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Bulk Read Multiple Cards
         * -------------
         *
         * List subset of Cards depending on various filtering flags.
         */
        CardsDomain.prototype.bulkReadCards = function (params) {
            return this.client.getDataState('/cards/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        CardsDomain.prototype.bulkReadCards2 = function (params) {
            return this.client.get('/cards/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Creating a single Card
         * -------------
         *
         * Enables one to create a single Card instance.
         */
        CardsDomain.prototype.createCard = function (body) {
            return this.client
                .post('/cards/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Card by Id
         * -------------
         *
         * Read Card by `id`.
         */
        CardsDomain.prototype.readCard = function (cardId) {
            return this.client.getDataState("/cards/" + cardId, { authorizationRequired: true });
        };
        CardsDomain.prototype.readCard2 = function (cardId) {
            return this.client.get("/cards/" + cardId, { authorizationRequired: true });
        };
        /**
         * Creating a single Card
         * -------------
         *
         * Enables one to create a single Card instance.
         */
        CardsDomain.prototype.updateCard = function (cardId, body) {
            return this.client
                .put("/cards/" + cardId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        CardsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        CardsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return CardsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var CategoriesDomain = (function () {
        function CategoriesDomain(client) {
            this.client = client;
        }
        /**
         * List Categories
         * -------------
         *
         * List Categories.
         */
        CategoriesDomain.prototype.bulkReadCategories = function () {
            return this.client.getDataState('/categories/', { responseMap: 'data', authorizationRequired: true });
        };
        CategoriesDomain.prototype.bulkReadCategories2 = function () {
            return this.client.get('/categories/', { responseMap: 'data', authorizationRequired: true });
        };
        CategoriesDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        CategoriesDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return CategoriesDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (BulkReadCategoriesResponseText) {
        BulkReadCategoriesResponseText["FORGOTTEN"] = "FORGOTTEN";
        BulkReadCategoriesResponseText["HOT"] = "HOT";
        BulkReadCategoriesResponseText["NOT_RECALLED"] = "NOT_RECALLED";
        BulkReadCategoriesResponseText["PROBLEMATIC"] = "PROBLEMATIC";
        BulkReadCategoriesResponseText["RECENTLY_ADDED"] = "RECENTLY_ADDED";
    })(exports.BulkReadCategoriesResponseText || (exports.BulkReadCategoriesResponseText = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var ContactsDomain = (function () {
        function ContactsDomain(client) {
            this.client = client;
        }
        /**
         * Create Anonymous Contact Attempt
         * -------------
         *
         * Enables one to send messages to CoSphere's support even if the sender is not authenticated.
         */
        ContactsDomain.prototype.createAnonymousContactAttempt = function (body) {
            return this.client
                .post('/contacts/anonymous/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Send Authenticated Contact Message
         * -------------
         *
         * Send the Contact Message immediately since it's already for an existing and authenticated user.
         */
        ContactsDomain.prototype.sendAuthenticatedContactMessage = function (body) {
            return this.client
                .post('/contacts/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Verify the contact attempt
         * -------------
         *
         * Verify the correctness of provided verification code and send the message to the CoSphere's support. This mechanism is used for anonymous users only.
         */
        ContactsDomain.prototype.verifyAnonymousContactAttempt = function (body) {
            return this.client
                .post('/contacts/anonymous/verify/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        ContactsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        ContactsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return ContactsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var DonationsDomain = (function () {
        function DonationsDomain(client) {
            this.client = client;
        }
        /**
         * Check if one can attempt a request displaying donation
         * -------------
         *
         * Since we don't want to overflow user with unnecessary requests for him donating we do it in a smarter way using set of heuristics that together help us to answer the following question: "Is it the best moment to ask for the donation?". Currently we use the following heuristics: - is account old enough? - whether user recently donated - whether we attempted recently to request donation from the user - if the user in a good mood (after doing some successful recalls)
         */
        DonationsDomain.prototype.checkIfCanAttemptDonation = function (params) {
            return this.client.getDataState('/payments/donations/can_attempt/', { params: params, authorizationRequired: true });
        };
        DonationsDomain.prototype.checkIfCanAttemptDonation2 = function (params) {
            return this.client.get('/payments/donations/can_attempt/', { params: params, authorizationRequired: true });
        };
        /**
         * Register anonymous donation
         * -------------
         *
         * One can perform a donation payment even if not being an authenticated user. Even in that case we cannot allow full anonymity and we must require at least email address to send information regarding the status of the payment.
         */
        DonationsDomain.prototype.createAnonymousDonation = function (body) {
            return this.client
                .post('/payments/donations/register_anonymous/', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Register donation from authenticated user
         * -------------
         *
         * One can perform a donation payment even as an authenticated user.
         */
        DonationsDomain.prototype.createDonation = function (body) {
            return this.client
                .post('/payments/donations/register/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create donation attempt for authenticated user
         * -------------
         *
         * Each Donation Attempt should be followed by creation of Donation Attempt model instance to reflect that fact. It allows one to track how many times we asked a certain user about the donation in order not to overflow that user with them and not to be too aggressive.
         */
        DonationsDomain.prototype.createDonationattempt = function (body) {
            return this.client
                .post('/payments/donations/attempts/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        DonationsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        DonationsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return DonationsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (CheckIfCanAttemptDonationQueryEvent) {
        CheckIfCanAttemptDonationQueryEvent["CLOSE"] = "CLOSE";
        CheckIfCanAttemptDonationQueryEvent["RECALL"] = "RECALL";
        CheckIfCanAttemptDonationQueryEvent["START"] = "START";
    })(exports.CheckIfCanAttemptDonationQueryEvent || (exports.CheckIfCanAttemptDonationQueryEvent = {}));
    (function (CreateAnonymousDonationResponseCurrency) {
        CreateAnonymousDonationResponseCurrency["PLN"] = "PLN";
    })(exports.CreateAnonymousDonationResponseCurrency || (exports.CreateAnonymousDonationResponseCurrency = {}));
    (function (CreateAnonymousDonationResponseProductType) {
        CreateAnonymousDonationResponseProductType["DONATION"] = "DONATION";
        CreateAnonymousDonationResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
        CreateAnonymousDonationResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
        CreateAnonymousDonationResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
        CreateAnonymousDonationResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
    })(exports.CreateAnonymousDonationResponseProductType || (exports.CreateAnonymousDonationResponseProductType = {}));
    (function (CreateAnonymousDonationResponseStatus) {
        CreateAnonymousDonationResponseStatus["CANCELED"] = "CANCELED";
        CreateAnonymousDonationResponseStatus["COMPLETED"] = "COMPLETED";
        CreateAnonymousDonationResponseStatus["NEW"] = "NEW";
        CreateAnonymousDonationResponseStatus["PENDING"] = "PENDING";
        CreateAnonymousDonationResponseStatus["REJECTED"] = "REJECTED";
    })(exports.CreateAnonymousDonationResponseStatus || (exports.CreateAnonymousDonationResponseStatus = {}));
    (function (CreateDonationResponseCurrency) {
        CreateDonationResponseCurrency["PLN"] = "PLN";
    })(exports.CreateDonationResponseCurrency || (exports.CreateDonationResponseCurrency = {}));
    (function (CreateDonationResponseProductType) {
        CreateDonationResponseProductType["DONATION"] = "DONATION";
        CreateDonationResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
        CreateDonationResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
        CreateDonationResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
        CreateDonationResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
    })(exports.CreateDonationResponseProductType || (exports.CreateDonationResponseProductType = {}));
    (function (CreateDonationResponseStatus) {
        CreateDonationResponseStatus["CANCELED"] = "CANCELED";
        CreateDonationResponseStatus["COMPLETED"] = "COMPLETED";
        CreateDonationResponseStatus["NEW"] = "NEW";
        CreateDonationResponseStatus["PENDING"] = "PENDING";
        CreateDonationResponseStatus["REJECTED"] = "REJECTED";
    })(exports.CreateDonationResponseStatus || (exports.CreateDonationResponseStatus = {}));
    (function (CreateDonationattemptBodyEvent) {
        CreateDonationattemptBodyEvent["CLOSE"] = "CLOSE";
        CreateDonationattemptBodyEvent["RECALL"] = "RECALL";
        CreateDonationattemptBodyEvent["START"] = "START";
    })(exports.CreateDonationattemptBodyEvent || (exports.CreateDonationattemptBodyEvent = {}));
    (function (CreateDonationattemptResponseEvent) {
        CreateDonationattemptResponseEvent["CLOSE"] = "CLOSE";
        CreateDonationattemptResponseEvent["RECALL"] = "RECALL";
        CreateDonationattemptResponseEvent["START"] = "START";
    })(exports.CreateDonationattemptResponseEvent || (exports.CreateDonationattemptResponseEvent = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var ExternalAppsDomain = (function () {
        function ExternalAppsDomain(client) {
            this.client = client;
        }
        /**
         * Authorize a given external app token
         * -------------
         *
         * Can be called by the API Gateway in order to authorize every request using provided token. It must be used only for external app tokens, which are used by the external apps to make calls on behalf of a given user.
         */
        ExternalAppsDomain.prototype.authorizeExternalAppAuthToken = function () {
            return this.client
                .post('/external/auth_tokens/authorize/', {}, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read External App Configuration
         */
        ExternalAppsDomain.prototype.createExternalAppAuthToken = function (body) {
            return this.client
                .post('/external/auth_tokens/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read External App configuration
         */
        ExternalAppsDomain.prototype.readExternalappconf = function (params) {
            return this.client.getDataState('/external/apps/', { params: params, authorizationRequired: true });
        };
        ExternalAppsDomain.prototype.readExternalappconf2 = function (params) {
            return this.client.get('/external/apps/', { params: params, authorizationRequired: true });
        };
        ExternalAppsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        ExternalAppsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return ExternalAppsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var FocusRecordsDomain = (function () {
        function FocusRecordsDomain(client) {
            this.client = client;
        }
        /**
         * Create Focus Record
         */
        FocusRecordsDomain.prototype.createFocusrecord = function (body) {
            return this.client
                .post('/focus_records/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Focus Record Summary
         */
        FocusRecordsDomain.prototype.readFocusRecordSummary = function () {
            return this.client.getDataState('/focus_records/summary/', { authorizationRequired: true });
        };
        FocusRecordsDomain.prototype.readFocusRecordSummary2 = function () {
            return this.client.get('/focus_records/summary/', { authorizationRequired: true });
        };
        FocusRecordsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        FocusRecordsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return FocusRecordsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var FragmentHashtagsDomain = (function () {
        function FragmentHashtagsDomain(client) {
            this.client = client;
        }
        /**
         * List Hashtags
         * -------------
         *
         * List Hashtags
         */
        FragmentHashtagsDomain.prototype.bulkReadFragmentHashtags = function (params) {
            return this.client.getDataState('/fragments/hashtags/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        FragmentHashtagsDomain.prototype.bulkReadFragmentHashtags2 = function (params) {
            return this.client.get('/fragments/hashtags/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * List Published Hashtags
         * -------------
         *
         * List Published Hashtags
         */
        FragmentHashtagsDomain.prototype.bulkReadPublishedFragmentHashtags = function (params) {
            return this.client.getDataState('/fragments/hashtags/published/', { params: params, responseMap: 'data', authorizationRequired: false });
        };
        FragmentHashtagsDomain.prototype.bulkReadPublishedFragmentHashtags2 = function (params) {
            return this.client.get('/fragments/hashtags/published/', { params: params, responseMap: 'data', authorizationRequired: false });
        };
        FragmentHashtagsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        FragmentHashtagsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return FragmentHashtagsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var FragmentWordsDomain = (function () {
        function FragmentWordsDomain(client) {
            this.client = client;
        }
        /**
         * List Words
         * -------------
         *
         * List Words
         */
        FragmentWordsDomain.prototype.bulkReadFragmentWords = function (params) {
            return this.client.getDataState('/fragments/words/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        FragmentWordsDomain.prototype.bulkReadFragmentWords2 = function (params) {
            return this.client.get('/fragments/words/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * List Published Words
         * -------------
         *
         * List Published Words
         */
        FragmentWordsDomain.prototype.bulkReadPublishedFragmentWords = function (params) {
            return this.client.getDataState('/fragments/words/published/', { params: params, responseMap: 'data', authorizationRequired: false });
        };
        FragmentWordsDomain.prototype.bulkReadPublishedFragmentWords2 = function (params) {
            return this.client.get('/fragments/words/published/', { params: params, responseMap: 'data', authorizationRequired: false });
        };
        FragmentWordsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        FragmentWordsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return FragmentWordsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var FragmentsDomain = (function () {
        function FragmentsDomain(client) {
            this.client = client;
        }
        /**
         * List Remote Fragments
         * -------------
         *
         * List Remote Fragments
         */
        FragmentsDomain.prototype.bulkReadFragments = function (params) {
            return this.client.getDataState('/fragments/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        FragmentsDomain.prototype.bulkReadFragments2 = function (params) {
            return this.client.get('/fragments/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * List Published Remote Fragments
         * -------------
         *
         * List Published Remote Fragments
         */
        FragmentsDomain.prototype.bulkReadPublishedFragments = function (params) {
            return this.client.getDataState('/fragments/published/', { params: params, responseMap: 'data', authorizationRequired: false });
        };
        FragmentsDomain.prototype.bulkReadPublishedFragments2 = function (params) {
            return this.client.get('/fragments/published/', { params: params, responseMap: 'data', authorizationRequired: false });
        };
        /**
         * Create Remote Fragment
         * -------------
         *
         * Create Remote Fragment
         */
        FragmentsDomain.prototype.createFragment = function () {
            return this.client
                .post('/fragments/', {}, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Delete Remote Fragment
         * -------------
         *
         * Delete Remote Fragment
         */
        FragmentsDomain.prototype.deleteFragment = function (fragmentId) {
            return this.client
                .delete("/fragments/" + fragmentId, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Merge Remote Fragment
         * -------------
         *
         * Merge Remote Fragment
         */
        FragmentsDomain.prototype.mergeFragment = function (fragmentId) {
            return this.client
                .post("/fragments/" + fragmentId + "/merge/", {}, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Publish Remote Fragment
         * -------------
         *
         * Publish Remote Fragment
         */
        FragmentsDomain.prototype.publishFragment = function (fragmentId) {
            return this.client
                .put("/fragments/" + fragmentId + "/publish/", {}, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Remote Fragment
         * -------------
         *
         * Read Remote Fragment
         */
        FragmentsDomain.prototype.readFragment = function (fragmentId) {
            return this.client.getDataState("/fragments/" + fragmentId, { authorizationRequired: true });
        };
        FragmentsDomain.prototype.readFragment2 = function (fragmentId) {
            return this.client.get("/fragments/" + fragmentId, { authorizationRequired: true });
        };
        /**
         * Read Fragment Diff
         * -------------
         *
         * Read Fragment Diff
         */
        FragmentsDomain.prototype.readFragmentDiff = function (fragmentId) {
            return this.client.getDataState("/fragments/" + fragmentId + "/diff/", { authorizationRequired: true });
        };
        FragmentsDomain.prototype.readFragmentDiff2 = function (fragmentId) {
            return this.client.get("/fragments/" + fragmentId + "/diff/", { authorizationRequired: true });
        };
        /**
         * Read Fragment Sample
         * -------------
         *
         * Read Fragment Sample
         */
        FragmentsDomain.prototype.readFragmentSample = function (fragmentId) {
            return this.client.getDataState("/fragments/" + fragmentId + "/sample/", { authorizationRequired: false });
        };
        FragmentsDomain.prototype.readFragmentSample2 = function (fragmentId) {
            return this.client.get("/fragments/" + fragmentId + "/sample/", { authorizationRequired: false });
        };
        /**
         * Update Remote Fragment
         * -------------
         *
         * Update Remote Fragment
         */
        FragmentsDomain.prototype.updateFragment = function (fragmentId, body) {
            return this.client
                .put("/fragments/" + fragmentId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        FragmentsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        FragmentsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return FragmentsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var GeometriesDomain = (function () {
        function GeometriesDomain(client) {
            this.client = client;
        }
        /**
         * List Geometries
         * -------------
         *
         * List Geometries.
         */
        GeometriesDomain.prototype.bulkReadGeometries = function (params) {
            return this.client.getDataState('/grid/geometries/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        GeometriesDomain.prototype.bulkReadGeometries2 = function (params) {
            return this.client.get('/grid/geometries/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Bulk Update Geometries
         * -------------
         *
         * Update in a Bulk list of Geometries.
         */
        GeometriesDomain.prototype.bulkUpdateGeometries = function (body) {
            return this.client
                .put('/grid/geometries/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Geometry by Card
         * -------------
         *
         * Read a Geometry entity given the id of Card which is the parent of the Geometry entity.
         */
        GeometriesDomain.prototype.readGeometryByCard = function (cardId) {
            return this.client.getDataState("/grid/geometries/by_card/" + cardId, { authorizationRequired: true });
        };
        GeometriesDomain.prototype.readGeometryByCard2 = function (cardId) {
            return this.client.get("/grid/geometries/by_card/" + cardId, { authorizationRequired: true });
        };
        /**
         * Read Graph
         * -------------
         *
         * Render and read Graph made out of all Cards and Links belonging to a given user.
         */
        GeometriesDomain.prototype.readGraph = function (params) {
            return this.client.getDataState('/grid/graphs/', { params: params, authorizationRequired: true });
        };
        GeometriesDomain.prototype.readGraph2 = function (params) {
            return this.client.get('/grid/graphs/', { params: params, authorizationRequired: true });
        };
        GeometriesDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        GeometriesDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return GeometriesDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var GossipDomain = (function () {
        function GossipDomain(client) {
            this.client = client;
        }
        /**
         * Bulk Read all supported spoken languages
         */
        GossipDomain.prototype.bulkReadSpeechLanguages = function () {
            return this.client.getDataState('/gossip/speech/languages/', { responseMap: 'data', authorizationRequired: true });
        };
        GossipDomain.prototype.bulkReadSpeechLanguages2 = function () {
            return this.client.get('/gossip/speech/languages/', { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Bulk Read all supported voice languages
         */
        GossipDomain.prototype.bulkReadTextLanguages = function () {
            return this.client.getDataState('/gossip/text/languages/', { responseMap: 'data', authorizationRequired: true });
        };
        GossipDomain.prototype.bulkReadTextLanguages2 = function () {
            return this.client.get('/gossip/text/languages/', { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Detect spoken language
         */
        GossipDomain.prototype.detectSpeechLanguages = function (body) {
            return this.client
                .post('/gossip/speech/detect_languages/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Detect written language
         */
        GossipDomain.prototype.detectTextLanguages = function (body) {
            return this.client
                .post('/gossip/text/detect_languages/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        GossipDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        GossipDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return GossipDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var HashtagsDomain = (function () {
        function HashtagsDomain(client) {
            this.client = client;
        }
        /**
         * List Hashtags
         * -------------
         *
         * Enables one to list a series of Hashtag instances. It accepts various query parameters such as: - `limit` - `offset` - `first_character`
         */
        HashtagsDomain.prototype.bulkReadHashtags = function (params) {
            return this.client.getDataState('/hashtags/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        HashtagsDomain.prototype.bulkReadHashtags2 = function (params) {
            return this.client.get('/hashtags/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Creating a single Hashtag
         * -------------
         *
         * Enables one to create a single Hashtag instance.
         */
        HashtagsDomain.prototype.createHashtag = function (body) {
            return this.client
                .post('/hashtags/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Removing a single Hashtag
         * -------------
         *
         * Enables one to detach a single Hashtag instance from a list cards given by `card_ids`.
         */
        HashtagsDomain.prototype.deleteHashtag = function (hashtagId, params) {
            return this.client
                .delete("/hashtags/" + hashtagId, { params: params, authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * List Hashtags TOC
         * -------------
         *
         * Enables one to list Hashtags Table of Contents made out of Hashtags. Note: Currently this endpoint returns only a flat list of hashtags with the count of Cards with which they're attached to. In the future though one could propose a mechanism which could calculate hierarchy between those hashtags (parent - child relationships) and ordering based on the knowledge grid topology. It accepts various query parameters such as: - `limit` - `offset`
         */
        HashtagsDomain.prototype.readHashtagsToc = function (params) {
            return this.client.getDataState('/hashtags/toc/', { params: params, authorizationRequired: true });
        };
        HashtagsDomain.prototype.readHashtagsToc2 = function (params) {
            return this.client.get('/hashtags/toc/', { params: params, authorizationRequired: true });
        };
        /**
         * Updating a single Hashtag
         * -------------
         *
         * Enables one to update a single Hashtag instance with a list of `card_ids` to which it should get attached to.
         */
        HashtagsDomain.prototype.updateHashtag = function (hashtagId, body) {
            return this.client
                .put("/hashtags/" + hashtagId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        HashtagsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        HashtagsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return HashtagsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var InvoicesDomain = (function () {
        function InvoicesDomain(client) {
            this.client = client;
        }
        /**
         * List all Invoices belonging to a given user
         * -------------
         *
         * Enables the the User to list all of the Invoices which were generated for his Donations or Subscription payments.
         */
        InvoicesDomain.prototype.bulkReadInvoices = function () {
            return this.client.getDataState('/payments/invoices/', { responseMap: 'data', authorizationRequired: true });
        };
        InvoicesDomain.prototype.bulkReadInvoices2 = function () {
            return this.client.get('/payments/invoices/', { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Calculate debt for a given user
         * -------------
         *
         * Calculate debt for a given user by searching for the latest unpaid invoice. It returns payment token which can be used in the PAID_WITH_DEFAULT_PAYMENT_CARD command
         */
        InvoicesDomain.prototype.calculateDebt = function () {
            return this.client.getDataState('/payments/invoices/debt/', { authorizationRequired: true });
        };
        InvoicesDomain.prototype.calculateDebt2 = function () {
            return this.client.get('/payments/invoices/debt/', { authorizationRequired: true });
        };
        InvoicesDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        InvoicesDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return InvoicesDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (BulkReadInvoicesResponseCurrency) {
        BulkReadInvoicesResponseCurrency["PLN"] = "PLN";
    })(exports.BulkReadInvoicesResponseCurrency || (exports.BulkReadInvoicesResponseCurrency = {}));
    (function (BulkReadInvoicesResponseProductType) {
        BulkReadInvoicesResponseProductType["DONATION"] = "DONATION";
        BulkReadInvoicesResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
        BulkReadInvoicesResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
        BulkReadInvoicesResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
        BulkReadInvoicesResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
    })(exports.BulkReadInvoicesResponseProductType || (exports.BulkReadInvoicesResponseProductType = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var LinksDomain = (function () {
        function LinksDomain(client) {
            this.client = client;
        }
        /**
         * Remove Link
         * -------------
         *
         * Remove a Link between two cards.
         */
        LinksDomain.prototype.deleteLink = function (fromCardId, toCardId) {
            return this.client
                .delete("/grid/links/" + fromCardId + "/" + toCardId, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read or Create Link
         * -------------
         *
         * Read or Create a Link between two cards.
         */
        LinksDomain.prototype.readOrCreateLink = function (body) {
            return this.client
                .post('/grid/links/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        LinksDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        LinksDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return LinksDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (ReadOrCreateLinkResponseKind) {
        ReadOrCreateLinkResponseKind["CARD"] = "CARD";
        ReadOrCreateLinkResponseKind["FRAGMENT"] = "FRAGMENT";
        ReadOrCreateLinkResponseKind["HASHTAG"] = "HASHTAG";
        ReadOrCreateLinkResponseKind["PATH"] = "PATH";
        ReadOrCreateLinkResponseKind["TERM"] = "TERM";
    })(exports.ReadOrCreateLinkResponseKind || (exports.ReadOrCreateLinkResponseKind = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var MediaitemsDomain = (function () {
        function MediaitemsDomain(client) {
            this.client = client;
        }
        /**
         * List MediaItems
         * -------------
         *
         * List MediaItems
         */
        MediaitemsDomain.prototype.bulkReadMediaitems = function (params) {
            return this.client.getDataState('/mediaitems/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        MediaitemsDomain.prototype.bulkReadMediaitems2 = function (params) {
            return this.client.get('/mediaitems/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Remove MediaItem
         * -------------
         *
         * Remove MediaItem instance.
         */
        MediaitemsDomain.prototype.deleteMediaitem = function (mediaitemId, params) {
            return this.client
                .delete("/mediaitems/" + mediaitemId, { params: params, authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read MediaItem
         * -------------
         *
         * Read MediaItem
         */
        MediaitemsDomain.prototype.readMediaitem = function (mediaitemId) {
            return this.client.getDataState("/mediaitems/" + mediaitemId, { authorizationRequired: true });
        };
        MediaitemsDomain.prototype.readMediaitem2 = function (mediaitemId) {
            return this.client.get("/mediaitems/" + mediaitemId, { authorizationRequired: true });
        };
        /**
         * Read By Process Id
         * -------------
         *
         * Read MediaItem by Process Id
         */
        MediaitemsDomain.prototype.readMediaitemByProcessId = function () {
            return this.client.getDataState('/mediaitems/by_process/(?P<process_id>[\w+\=]+)', { authorizationRequired: true });
        };
        MediaitemsDomain.prototype.readMediaitemByProcessId2 = function () {
            return this.client.get('/mediaitems/by_process/(?P<process_id>[\w+\=]+)', { authorizationRequired: true });
        };
        /**
         * Read or Create MediaItem
         * -------------
         *
         * Read or Create MediaItem instance.
         */
        MediaitemsDomain.prototype.readOrCreateMediaitem = function (body) {
            return this.client
                .post('/mediaitems/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Update MediaItem
         * -------------
         *
         * Update MediaItem instance.
         */
        MediaitemsDomain.prototype.updateMediaitem = function (mediaitemId, body) {
            return this.client
                .put("/mediaitems/" + mediaitemId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Update MediaItem Representation
         * -------------
         *
         * Update given MediaItem with only the fields which are decided externally (using external services). Fields like: - `web_representations` - `thumbnail_uri` - `meta` - `text` All of those fields are computed in smarter way in order to make the MediaItem way better in a semantic sense. Those fields are perceived as the `representation` of a given MediaItem since they contains information about how to display a given MediaItem, how to understand it etc. It goes beyond the simple abstract data oriented representation (uri, extension etc.).
         */
        MediaitemsDomain.prototype.updateMediaitemRepresentation = function (mediaitemId, body) {
            return this.client
                .put("/mediaitems/" + mediaitemId + "/representation/", body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        MediaitemsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        MediaitemsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return MediaitemsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var NotificationsDomain = (function () {
        function NotificationsDomain(client) {
            this.client = client;
        }
        /**
         * Acknowledge Notification
         * -------------
         *
         * Acknowledge Notification
         */
        NotificationsDomain.prototype.acknowledgeNotification = function (notificationId) {
            return this.client
                .put("/notifications/" + notificationId + "/acknowledge/", {}, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * List Notifications
         * -------------
         *
         * List Notifications
         */
        NotificationsDomain.prototype.bulkReadNotifications = function (params) {
            return this.client.getDataState('/notifications/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        NotificationsDomain.prototype.bulkReadNotifications2 = function (params) {
            return this.client.get('/notifications/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        NotificationsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        NotificationsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return NotificationsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (BulkReadNotificationsResponseKind) {
        BulkReadNotificationsResponseKind["FRAGMENT_UPDATE"] = "FRAGMENT_UPDATE";
    })(exports.BulkReadNotificationsResponseKind || (exports.BulkReadNotificationsResponseKind = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var NounsDomain = (function () {
        function NounsDomain(client) {
            this.client = client;
        }
        /**
         * Bulk Read Noun Project Icons
         */
        NounsDomain.prototype.bulkReadIcons = function (params) {
            return this.client.getDataState('/nouns/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        NounsDomain.prototype.bulkReadIcons2 = function (params) {
            return this.client.get('/nouns/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        NounsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        NounsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return NounsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var PathsDomain = (function () {
        function PathsDomain(client) {
            this.client = client;
        }
        /**
         * Delete Paths
         * -------------
         *
         * Endpoint for Deleting multiple Paths.
         */
        PathsDomain.prototype.bulkDeletePaths = function (params) {
            return this.client
                .delete('/paths/', { params: params, authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * List Paths
         * -------------
         *
         * List all user's Paths
         */
        PathsDomain.prototype.bulkReadPaths = function (params) {
            return this.client.getDataState('/paths/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        PathsDomain.prototype.bulkReadPaths2 = function (params) {
            return this.client.get('/paths/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Create Path
         * -------------
         *
         * Endpoint for Creating Path.
         */
        PathsDomain.prototype.createPath = function (body) {
            return this.client
                .post('/paths/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Path
         * -------------
         *
         * Read single Path
         */
        PathsDomain.prototype.readPath = function (pathId) {
            return this.client.getDataState("/paths/" + pathId, { authorizationRequired: true });
        };
        PathsDomain.prototype.readPath2 = function (pathId) {
            return this.client.get("/paths/" + pathId, { authorizationRequired: true });
        };
        /**
         * Update Path
         * -------------
         *
         * Endpoint for Updating Path.
         */
        PathsDomain.prototype.updatePath = function (pathId, body) {
            return this.client
                .put("/paths/" + pathId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        PathsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        PathsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return PathsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var PaymentCardsDomain = (function () {
        function PaymentCardsDomain(client) {
            this.client = client;
        }
        /**
         * Mark a given Payment Card as a default one
         * -------------
         *
         * Enables the the User to mark a specific Payment Card as a default one, meaning that it will be used for all upcoming payments. Marking Payment Card as a default one automatically leads to the unmarking of any Payment Card which was default one before the invocation of the command.
         */
        PaymentCardsDomain.prototype.asDefaultMarkPaymentcard = function (paymentCardId) {
            return this.client
                .put("/payments/payment_cards/" + paymentCardId + "/mark_as_default/", {}, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * List all Payment Cards belonging to a given user
         * -------------
         *
         * Enables the the User to list all of the Payment Cards which were added by him / her. Among all returned Payment Cards there must be one and only one which is marked as **default**.
         */
        PaymentCardsDomain.prototype.bulkReadPaymentcards = function () {
            return this.client.getDataState('/payments/payment_cards/', { responseMap: 'data', authorizationRequired: true });
        };
        PaymentCardsDomain.prototype.bulkReadPaymentcards2 = function () {
            return this.client.get('/payments/payment_cards/', { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Create a Payment Card
         * -------------
         *
         * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on. Using the optional `mark_as_default` field one can mark just created Payment Card as the default one.
         */
        PaymentCardsDomain.prototype.createPaymentcard = function (body) {
            return this.client
                .post('/payments/payment_cards/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Remove a given Payment Card belonging to a given user
         * -------------
         *
         * Enables the the User to remove a specific Payment Card which were added by him / her. Payment Card can be removed only if it's not a default one.
         */
        PaymentCardsDomain.prototype.deletePaymentcard = function (paymentCardId) {
            return this.client
                .delete("/payments/payment_cards/" + paymentCardId, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Pay using the default Payment Card
         * -------------
         *
         * User is allowed only to perform payments against her default Payment Card. In other words on order to use a given Payment Card one has to mark is as default. Also one is not allowed to perform such payments freely and therefore we expect to get a `payment_token` inside which another piece of our system encoded allowed sum to be paid.
         */
        PaymentCardsDomain.prototype.payWithDefaultPaymentCard = function (body) {
            return this.client
                .post('/payments/payment_cards/pay_with_default/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create a Payment Card
         * -------------
         *
         * Enables the the User to add new Payment Card, which could be needed in cases when the User would like to replace existing Payment Card because: - it expired - is empty - the User prefers another one to be used from now on
         */
        PaymentCardsDomain.prototype.renderPaymentCardWidget = function () {
            return this.client.getDataState('/payments/payment_cards/widget/', { authorizationRequired: true });
        };
        PaymentCardsDomain.prototype.renderPaymentCardWidget2 = function () {
            return this.client.get('/payments/payment_cards/widget/', { authorizationRequired: true });
        };
        PaymentCardsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        PaymentCardsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return PaymentCardsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (BulkReadPaymentcardsResponseCurrency) {
        BulkReadPaymentcardsResponseCurrency["PLN"] = "PLN";
    })(exports.BulkReadPaymentcardsResponseCurrency || (exports.BulkReadPaymentcardsResponseCurrency = {}));
    (function (BulkReadPaymentcardsResponseProductType) {
        BulkReadPaymentcardsResponseProductType["DONATION"] = "DONATION";
        BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
        BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
        BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
        BulkReadPaymentcardsResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
    })(exports.BulkReadPaymentcardsResponseProductType || (exports.BulkReadPaymentcardsResponseProductType = {}));
    (function (BulkReadPaymentcardsResponseStatus) {
        BulkReadPaymentcardsResponseStatus["CANCELED"] = "CANCELED";
        BulkReadPaymentcardsResponseStatus["COMPLETED"] = "COMPLETED";
        BulkReadPaymentcardsResponseStatus["NEW"] = "NEW";
        BulkReadPaymentcardsResponseStatus["PENDING"] = "PENDING";
        BulkReadPaymentcardsResponseStatus["REJECTED"] = "REJECTED";
    })(exports.BulkReadPaymentcardsResponseStatus || (exports.BulkReadPaymentcardsResponseStatus = {}));
    (function (CreatePaymentcardResponseCurrency) {
        CreatePaymentcardResponseCurrency["PLN"] = "PLN";
    })(exports.CreatePaymentcardResponseCurrency || (exports.CreatePaymentcardResponseCurrency = {}));
    (function (CreatePaymentcardResponseProductType) {
        CreatePaymentcardResponseProductType["DONATION"] = "DONATION";
        CreatePaymentcardResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
        CreatePaymentcardResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
        CreatePaymentcardResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
        CreatePaymentcardResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
    })(exports.CreatePaymentcardResponseProductType || (exports.CreatePaymentcardResponseProductType = {}));
    (function (CreatePaymentcardResponseStatus) {
        CreatePaymentcardResponseStatus["CANCELED"] = "CANCELED";
        CreatePaymentcardResponseStatus["COMPLETED"] = "COMPLETED";
        CreatePaymentcardResponseStatus["NEW"] = "NEW";
        CreatePaymentcardResponseStatus["PENDING"] = "PENDING";
        CreatePaymentcardResponseStatus["REJECTED"] = "REJECTED";
    })(exports.CreatePaymentcardResponseStatus || (exports.CreatePaymentcardResponseStatus = {}));
    (function (PayWithDefaultPaymentCardResponseCurrency) {
        PayWithDefaultPaymentCardResponseCurrency["PLN"] = "PLN";
    })(exports.PayWithDefaultPaymentCardResponseCurrency || (exports.PayWithDefaultPaymentCardResponseCurrency = {}));
    (function (PayWithDefaultPaymentCardResponseProductType) {
        PayWithDefaultPaymentCardResponseProductType["DONATION"] = "DONATION";
        PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
        PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
        PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
        PayWithDefaultPaymentCardResponseProductType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
    })(exports.PayWithDefaultPaymentCardResponseProductType || (exports.PayWithDefaultPaymentCardResponseProductType = {}));
    (function (PayWithDefaultPaymentCardResponseStatus) {
        PayWithDefaultPaymentCardResponseStatus["CANCELED"] = "CANCELED";
        PayWithDefaultPaymentCardResponseStatus["COMPLETED"] = "COMPLETED";
        PayWithDefaultPaymentCardResponseStatus["NEW"] = "NEW";
        PayWithDefaultPaymentCardResponseStatus["PENDING"] = "PENDING";
        PayWithDefaultPaymentCardResponseStatus["REJECTED"] = "REJECTED";
    })(exports.PayWithDefaultPaymentCardResponseStatus || (exports.PayWithDefaultPaymentCardResponseStatus = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var PaymentsDomain = (function () {
        function PaymentsDomain(client) {
            this.client = client;
        }
        /**
         * Update the status of a given Payment
         * -------------
         *
         * Update the Payment instance identified by the `session_id`. This command is for external use only therefore it doesn't expose internal ids of the payments but rather session id.
         */
        PaymentsDomain.prototype.updatePaymentStatus = function (body) {
            return this.client
                .post('/payments/(?P<session_id>[\w\-]+)', body, { authorizationRequired: false })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        PaymentsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        PaymentsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return PaymentsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var ProcessesDomain = (function () {
        function ProcessesDomain(client) {
            this.client = client;
        }
        /**
         * Create Deletion Process
         */
        ProcessesDomain.prototype.createDeletionProcess = function (body) {
            return this.client
                .post('/mediafiles/processes/deletions/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Download Process
         */
        ProcessesDomain.prototype.createDownloadProcess = function (body) {
            return this.client
                .post('/mediafiles/processes/downloads/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Media Lock
         */
        ProcessesDomain.prototype.createMediaLock = function (body) {
            return this.client
                .post('/mediafiles/locks/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Upload Process
         */
        ProcessesDomain.prototype.createUploadProcess = function (body) {
            return this.client
                .post('/mediafiles/processes/uploads/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read invariants for a given uri
         */
        ProcessesDomain.prototype.readInvariants = function (params) {
            return this.client.getDataState('/mediafiles/invariants/', { params: params, authorizationRequired: true });
        };
        ProcessesDomain.prototype.readInvariants2 = function (params) {
            return this.client.get('/mediafiles/invariants/', { params: params, authorizationRequired: true });
        };
        /**
         * Create Media Lock
         */
        ProcessesDomain.prototype.readProcessState = function (params) {
            return this.client.getDataState('/mediafiles/processes/', { params: params, authorizationRequired: true });
        };
        ProcessesDomain.prototype.readProcessState2 = function (params) {
            return this.client.get('/mediafiles/processes/', { params: params, authorizationRequired: true });
        };
        /**
         * Sign Process dedicated to upload and conversion of media file
         */
        ProcessesDomain.prototype.signProcess = function (params) {
            return this.client.getDataState('/mediafiles/processes/sign/', { params: params, authorizationRequired: true });
        };
        ProcessesDomain.prototype.signProcess2 = function (params) {
            return this.client.get('/mediafiles/processes/sign/', { params: params, authorizationRequired: true });
        };
        /**
         * Watch conversion status
         * -------------
         *
         * Endpoint called by the external conversion service.
         */
        ProcessesDomain.prototype.watchConversionStatus = function (waiterId, params) {
            return this.client.getDataState("/mediafiles/convert_processes/(?P<process_id>[0-9a-zA-Z_-=]+)/" + waiterId, { params: params, authorizationRequired: false });
        };
        ProcessesDomain.prototype.watchConversionStatus2 = function (waiterId, params) {
            return this.client.get("/mediafiles/convert_processes/(?P<process_id>[0-9a-zA-Z_-=]+)/" + waiterId, { params: params, authorizationRequired: false });
        };
        ProcessesDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        ProcessesDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return ProcessesDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var QuizzerDomain = (function () {
        function QuizzerDomain(client) {
            this.client = client;
        }
        /**
         * Build Read Quiz Attempts
         */
        QuizzerDomain.prototype.bulkReadQuizattempts = function (quizId) {
            return this.client.getDataState("/quizzes/" + quizId + "/attempts/", { responseMap: 'data', authorizationRequired: true });
        };
        QuizzerDomain.prototype.bulkReadQuizattempts2 = function (quizId) {
            return this.client.get("/quizzes/" + quizId + "/attempts/", { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Bulk Read Quizzes
         */
        QuizzerDomain.prototype.bulkReadQuizzes = function () {
            return this.client.getDataState('/quizzes/', { responseMap: 'data', authorizationRequired: true });
        };
        QuizzerDomain.prototype.bulkReadQuizzes2 = function () {
            return this.client.get('/quizzes/', { responseMap: 'data', authorizationRequired: true });
        };
        /**
         * Create Quiz
         */
        QuizzerDomain.prototype.createQuiz = function (body) {
            return this.client
                .post('/quizzes/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Create Quiz Attempt
         */
        QuizzerDomain.prototype.createQuizattempt = function (quizId, body) {
            return this.client
                .post("/quizzes/" + quizId + "/attempts/", body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Delete Quiz
         */
        QuizzerDomain.prototype.deleteQuiz = function (quizId) {
            return this.client
                .delete("/quizzes/" + quizId, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Quiz
         */
        QuizzerDomain.prototype.readQuiz = function (quizId) {
            return this.client.getDataState("/quizzes/" + quizId, { authorizationRequired: true });
        };
        QuizzerDomain.prototype.readQuiz2 = function (quizId) {
            return this.client.get("/quizzes/" + quizId, { authorizationRequired: true });
        };
        /**
         * Update Quiz
         */
        QuizzerDomain.prototype.updateQuiz = function (quizId, body) {
            return this.client
                .put("/quizzes/" + quizId, body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        QuizzerDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        QuizzerDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return QuizzerDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var RecallDomain = (function () {
        function RecallDomain(client) {
            this.client = client;
        }
        /**
         * Create Recall Session
         * -------------
         *
         * Render Recall Session composed out of the sequence of Cards that should be recalled in a given order. Based on the RecallAttempt stats recommend another Card to recall in order to maximize the recall speed and success rate.
         */
        RecallDomain.prototype.createRecallSession = function (body) {
            return this.client
                .post('/recall/sessions/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        /**
         * Read Recall Summary
         * -------------
         *
         * Read summary stats for cards and their recall_score for a given User.
         */
        RecallDomain.prototype.readRecallSummary = function () {
            return this.client.getDataState('/recall/summary/', { authorizationRequired: true });
        };
        RecallDomain.prototype.readRecallSummary2 = function () {
            return this.client.get('/recall/summary/', { authorizationRequired: true });
        };
        RecallDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        RecallDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return RecallDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var SubscriptionsDomain = (function () {
        function SubscriptionsDomain(client) {
            this.client = client;
        }
        /**
         * Request a subscription change
         * -------------
         *
         * Whenever the user wants to change her subscription it must happen through this endpoint. It's still possible that the subscription will change without user asking for it, but that can happen when downgrading due to missing payment.
         */
        SubscriptionsDomain.prototype.changeSubscription = function (body) {
            return this.client
                .put('/payments/subscription/', body, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        SubscriptionsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        SubscriptionsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return SubscriptionsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (ChangeSubscriptionBodySubscriptionType) {
        ChangeSubscriptionBodySubscriptionType["FREE"] = "FREE";
        ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_LEARNER_MONTHLY"] = "SUBSCRIPTION_LEARNER_MONTHLY";
        ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_LEARNER_YEARLY"] = "SUBSCRIPTION_LEARNER_YEARLY";
        ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_MENTOR_MONTHLY"] = "SUBSCRIPTION_MENTOR_MONTHLY";
        ChangeSubscriptionBodySubscriptionType["SUBSCRIPTION_MENTOR_YEARLY"] = "SUBSCRIPTION_MENTOR_YEARLY";
    })(exports.ChangeSubscriptionBodySubscriptionType || (exports.ChangeSubscriptionBodySubscriptionType = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var TasksDomain = (function () {
        function TasksDomain(client) {
            this.client = client;
        }
        /**
         * List Tasks
         * -------------
         *
         * List tasks
         */
        TasksDomain.prototype.bulkReadTasks = function (params) {
            return this.client.getDataState('/tasks/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        TasksDomain.prototype.bulkReadTasks2 = function (params) {
            return this.client.get('/tasks/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        /**
         * List Task Bins
         * -------------
         *
         * List Tasks Bins
         */
        TasksDomain.prototype.bulkReadTaskBins = function (params) {
            return this.client.getDataState('/tasks/bins/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        TasksDomain.prototype.bulkReadTaskBins2 = function (params) {
            return this.client.get('/tasks/bins/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        TasksDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        TasksDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return TasksDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    (function (BulkReadTasksQueryQueueType) {
        BulkReadTasksQueryQueueType["DN"] = "DN";
        BulkReadTasksQueryQueueType["HP"] = "HP";
        BulkReadTasksQueryQueueType["OT"] = "OT";
        BulkReadTasksQueryQueueType["PR"] = "PR";
    })(exports.BulkReadTasksQueryQueueType || (exports.BulkReadTasksQueryQueueType = {}));
    (function (BulkReadTasksResponseQueueType) {
        BulkReadTasksResponseQueueType["DN"] = "DN";
        BulkReadTasksResponseQueueType["HP"] = "HP";
        BulkReadTasksResponseQueueType["OT"] = "OT";
        BulkReadTasksResponseQueueType["PR"] = "PR";
    })(exports.BulkReadTasksResponseQueueType || (exports.BulkReadTasksResponseQueueType = {}));
    (function (BulkReadTaskBinsQueryQueueType) {
        BulkReadTaskBinsQueryQueueType["DN"] = "DN";
        BulkReadTaskBinsQueryQueueType["HP"] = "HP";
        BulkReadTaskBinsQueryQueueType["OT"] = "OT";
        BulkReadTaskBinsQueryQueueType["PR"] = "PR";
    })(exports.BulkReadTaskBinsQueryQueueType || (exports.BulkReadTaskBinsQueryQueueType = {}));
    (function (BulkReadTaskBinsResponseQueueType) {
        BulkReadTaskBinsResponseQueueType["DN"] = "DN";
        BulkReadTaskBinsResponseQueueType["HP"] = "HP";
        BulkReadTaskBinsResponseQueueType["OT"] = "OT";
        BulkReadTaskBinsResponseQueueType["PR"] = "PR";
    })(exports.BulkReadTaskBinsResponseQueueType || (exports.BulkReadTaskBinsResponseQueueType = {}));

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var WordsDomain = (function () {
        function WordsDomain(client) {
            this.client = client;
        }
        /**
         * List Words
         * -------------
         *
         * List Words by first character. It allows one to fetch list of words by first character.
         */
        WordsDomain.prototype.bulkReadWords = function (params) {
            return this.client.getDataState('/words/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        WordsDomain.prototype.bulkReadWords2 = function (params) {
            return this.client.get('/words/', { params: params, responseMap: 'data', authorizationRequired: true });
        };
        WordsDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        WordsDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return WordsDomain;
    }());

    /**
      * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
      * OVERWRITTEN
      */
    var APIService = (function () {
        function APIService(injector) {
            this.injector = injector;
        }
        Object.defineProperty(APIService.prototype, "account_settingsDomain", {
            get: function () {
                if (!this._account_settingsDomain) {
                    this._account_settingsDomain = this.injector.get(AccountSettingsDomain);
                }
                return this._account_settingsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.readAccountsetting = function () {
            return this.account_settingsDomain.readAccountsetting();
        };
        APIService.prototype.readAccountsetting2 = function () {
            return this.account_settingsDomain.readAccountsetting2();
        };
        APIService.prototype.updateAccountsetting = function (body) {
            return this.account_settingsDomain.updateAccountsetting(body);
        };
        Object.defineProperty(APIService.prototype, "accountsDomain", {
            get: function () {
                if (!this._accountsDomain) {
                    this._accountsDomain = this.injector.get(AccountsDomain);
                }
                return this._accountsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.activateAccount = function (body) {
            return this.accountsDomain.activateAccount(body);
        };
        APIService.prototype.bulkReadAccounts = function (params) {
            return this.accountsDomain.bulkReadAccounts(params);
        };
        APIService.prototype.bulkReadAccounts2 = function (params) {
            return this.accountsDomain.bulkReadAccounts2(params);
        };
        APIService.prototype.changePassword = function (body) {
            return this.accountsDomain.changePassword(body);
        };
        APIService.prototype.createAccount = function (body) {
            return this.accountsDomain.createAccount(body);
        };
        APIService.prototype.readAccount = function () {
            return this.accountsDomain.readAccount();
        };
        APIService.prototype.readAccount2 = function () {
            return this.accountsDomain.readAccount2();
        };
        APIService.prototype.resetPassword = function (body) {
            return this.accountsDomain.resetPassword(body);
        };
        APIService.prototype.sendAccountActivationEmail = function (body) {
            return this.accountsDomain.sendAccountActivationEmail(body);
        };
        APIService.prototype.sendResetPasswordEmail = function (body) {
            return this.accountsDomain.sendResetPasswordEmail(body);
        };
        APIService.prototype.updateAccount = function (body) {
            return this.accountsDomain.updateAccount(body);
        };
        Object.defineProperty(APIService.prototype, "attempt_statsDomain", {
            get: function () {
                if (!this._attempt_statsDomain) {
                    this._attempt_statsDomain = this.injector.get(AttemptStatsDomain);
                }
                return this._attempt_statsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadAttemptstats = function (params) {
            return this.attempt_statsDomain.bulkReadAttemptstats(params);
        };
        APIService.prototype.bulkReadAttemptstats2 = function (params) {
            return this.attempt_statsDomain.bulkReadAttemptstats2(params);
        };
        APIService.prototype.createAttemptstat = function (body) {
            return this.attempt_statsDomain.createAttemptstat(body);
        };
        APIService.prototype.createExternalAttemptStat = function (body) {
            return this.attempt_statsDomain.createExternalAttemptStat(body);
        };
        Object.defineProperty(APIService.prototype, "attemptsDomain", {
            get: function () {
                if (!this._attemptsDomain) {
                    this._attemptsDomain = this.injector.get(AttemptsDomain);
                }
                return this._attemptsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadAttemptsByCards = function (cardId) {
            return this.attemptsDomain.bulkReadAttemptsByCards(cardId);
        };
        APIService.prototype.bulkReadAttemptsByCards2 = function (cardId) {
            return this.attemptsDomain.bulkReadAttemptsByCards2(cardId);
        };
        APIService.prototype.createAttempt = function (body) {
            return this.attemptsDomain.createAttempt(body);
        };
        APIService.prototype.updateAttempt = function (attemptId, body) {
            return this.attemptsDomain.updateAttempt(attemptId, body);
        };
        Object.defineProperty(APIService.prototype, "auth_tokensDomain", {
            get: function () {
                if (!this._auth_tokensDomain) {
                    this._auth_tokensDomain = this.injector.get(AuthTokensDomain);
                }
                return this._auth_tokensDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.authorizeAuthToken = function () {
            return this.auth_tokensDomain.authorizeAuthToken();
        };
        APIService.prototype.createAuthToken = function (body) {
            return this.auth_tokensDomain.createAuthToken(body);
        };
        APIService.prototype.createFacebookBasedAuthToken = function (body) {
            return this.auth_tokensDomain.createFacebookBasedAuthToken(body);
        };
        APIService.prototype.createFacebookBasedMobileAuthToken = function (body) {
            return this.auth_tokensDomain.createFacebookBasedMobileAuthToken(body);
        };
        APIService.prototype.createGoogleBasedAuthToken = function (body) {
            return this.auth_tokensDomain.createGoogleBasedAuthToken(body);
        };
        APIService.prototype.createGoogleBasedMobileAuthToken = function (body) {
            return this.auth_tokensDomain.createGoogleBasedMobileAuthToken(body);
        };
        APIService.prototype.updateAuthToken = function () {
            return this.auth_tokensDomain.updateAuthToken();
        };
        Object.defineProperty(APIService.prototype, "bricksDomain", {
            get: function () {
                if (!this._bricksDomain) {
                    this._bricksDomain = this.injector.get(BricksDomain);
                }
                return this._bricksDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadGameattempts = function (gameId) {
            return this.bricksDomain.bulkReadGameattempts(gameId);
        };
        APIService.prototype.bulkReadGameattempts2 = function (gameId) {
            return this.bricksDomain.bulkReadGameattempts2(gameId);
        };
        APIService.prototype.bulkReadGames = function () {
            return this.bricksDomain.bulkReadGames();
        };
        APIService.prototype.bulkReadGames2 = function () {
            return this.bricksDomain.bulkReadGames2();
        };
        APIService.prototype.createGame = function (body) {
            return this.bricksDomain.createGame(body);
        };
        APIService.prototype.createGameattempt = function (gameId, body) {
            return this.bricksDomain.createGameattempt(gameId, body);
        };
        APIService.prototype.deleteGame = function (gameId) {
            return this.bricksDomain.deleteGame(gameId);
        };
        APIService.prototype.readGame = function (gameId) {
            return this.bricksDomain.readGame(gameId);
        };
        APIService.prototype.readGame2 = function (gameId) {
            return this.bricksDomain.readGame2(gameId);
        };
        APIService.prototype.updateGame = function (gameId, body) {
            return this.bricksDomain.updateGame(gameId, body);
        };
        Object.defineProperty(APIService.prototype, "cardsDomain", {
            get: function () {
                if (!this._cardsDomain) {
                    this._cardsDomain = this.injector.get(CardsDomain);
                }
                return this._cardsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkDeleteCards = function (params) {
            return this.cardsDomain.bulkDeleteCards(params);
        };
        APIService.prototype.bulkReadCards = function (params) {
            return this.cardsDomain.bulkReadCards(params);
        };
        APIService.prototype.bulkReadCards2 = function (params) {
            return this.cardsDomain.bulkReadCards2(params);
        };
        APIService.prototype.createCard = function (body) {
            return this.cardsDomain.createCard(body);
        };
        APIService.prototype.readCard = function (cardId) {
            return this.cardsDomain.readCard(cardId);
        };
        APIService.prototype.readCard2 = function (cardId) {
            return this.cardsDomain.readCard2(cardId);
        };
        APIService.prototype.updateCard = function (cardId, body) {
            return this.cardsDomain.updateCard(cardId, body);
        };
        Object.defineProperty(APIService.prototype, "categoriesDomain", {
            get: function () {
                if (!this._categoriesDomain) {
                    this._categoriesDomain = this.injector.get(CategoriesDomain);
                }
                return this._categoriesDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadCategories = function () {
            return this.categoriesDomain.bulkReadCategories();
        };
        APIService.prototype.bulkReadCategories2 = function () {
            return this.categoriesDomain.bulkReadCategories2();
        };
        Object.defineProperty(APIService.prototype, "contactsDomain", {
            get: function () {
                if (!this._contactsDomain) {
                    this._contactsDomain = this.injector.get(ContactsDomain);
                }
                return this._contactsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.createAnonymousContactAttempt = function (body) {
            return this.contactsDomain.createAnonymousContactAttempt(body);
        };
        APIService.prototype.sendAuthenticatedContactMessage = function (body) {
            return this.contactsDomain.sendAuthenticatedContactMessage(body);
        };
        APIService.prototype.verifyAnonymousContactAttempt = function (body) {
            return this.contactsDomain.verifyAnonymousContactAttempt(body);
        };
        Object.defineProperty(APIService.prototype, "donationsDomain", {
            get: function () {
                if (!this._donationsDomain) {
                    this._donationsDomain = this.injector.get(DonationsDomain);
                }
                return this._donationsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.checkIfCanAttemptDonation = function (params) {
            return this.donationsDomain.checkIfCanAttemptDonation(params);
        };
        APIService.prototype.checkIfCanAttemptDonation2 = function (params) {
            return this.donationsDomain.checkIfCanAttemptDonation2(params);
        };
        APIService.prototype.createAnonymousDonation = function (body) {
            return this.donationsDomain.createAnonymousDonation(body);
        };
        APIService.prototype.createDonation = function (body) {
            return this.donationsDomain.createDonation(body);
        };
        APIService.prototype.createDonationattempt = function (body) {
            return this.donationsDomain.createDonationattempt(body);
        };
        Object.defineProperty(APIService.prototype, "external_appsDomain", {
            get: function () {
                if (!this._external_appsDomain) {
                    this._external_appsDomain = this.injector.get(ExternalAppsDomain);
                }
                return this._external_appsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.authorizeExternalAppAuthToken = function () {
            return this.external_appsDomain.authorizeExternalAppAuthToken();
        };
        APIService.prototype.createExternalAppAuthToken = function (body) {
            return this.external_appsDomain.createExternalAppAuthToken(body);
        };
        APIService.prototype.readExternalappconf = function (params) {
            return this.external_appsDomain.readExternalappconf(params);
        };
        APIService.prototype.readExternalappconf2 = function (params) {
            return this.external_appsDomain.readExternalappconf2(params);
        };
        Object.defineProperty(APIService.prototype, "focus_recordsDomain", {
            get: function () {
                if (!this._focus_recordsDomain) {
                    this._focus_recordsDomain = this.injector.get(FocusRecordsDomain);
                }
                return this._focus_recordsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.createFocusrecord = function (body) {
            return this.focus_recordsDomain.createFocusrecord(body);
        };
        APIService.prototype.readFocusRecordSummary = function () {
            return this.focus_recordsDomain.readFocusRecordSummary();
        };
        APIService.prototype.readFocusRecordSummary2 = function () {
            return this.focus_recordsDomain.readFocusRecordSummary2();
        };
        Object.defineProperty(APIService.prototype, "fragment_hashtagsDomain", {
            get: function () {
                if (!this._fragment_hashtagsDomain) {
                    this._fragment_hashtagsDomain = this.injector.get(FragmentHashtagsDomain);
                }
                return this._fragment_hashtagsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadFragmentHashtags = function (params) {
            return this.fragment_hashtagsDomain.bulkReadFragmentHashtags(params);
        };
        APIService.prototype.bulkReadFragmentHashtags2 = function (params) {
            return this.fragment_hashtagsDomain.bulkReadFragmentHashtags2(params);
        };
        APIService.prototype.bulkReadPublishedFragmentHashtags = function (params) {
            return this.fragment_hashtagsDomain.bulkReadPublishedFragmentHashtags(params);
        };
        APIService.prototype.bulkReadPublishedFragmentHashtags2 = function (params) {
            return this.fragment_hashtagsDomain.bulkReadPublishedFragmentHashtags2(params);
        };
        Object.defineProperty(APIService.prototype, "fragment_wordsDomain", {
            get: function () {
                if (!this._fragment_wordsDomain) {
                    this._fragment_wordsDomain = this.injector.get(FragmentWordsDomain);
                }
                return this._fragment_wordsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadFragmentWords = function (params) {
            return this.fragment_wordsDomain.bulkReadFragmentWords(params);
        };
        APIService.prototype.bulkReadFragmentWords2 = function (params) {
            return this.fragment_wordsDomain.bulkReadFragmentWords2(params);
        };
        APIService.prototype.bulkReadPublishedFragmentWords = function (params) {
            return this.fragment_wordsDomain.bulkReadPublishedFragmentWords(params);
        };
        APIService.prototype.bulkReadPublishedFragmentWords2 = function (params) {
            return this.fragment_wordsDomain.bulkReadPublishedFragmentWords2(params);
        };
        Object.defineProperty(APIService.prototype, "fragmentsDomain", {
            get: function () {
                if (!this._fragmentsDomain) {
                    this._fragmentsDomain = this.injector.get(FragmentsDomain);
                }
                return this._fragmentsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadFragments = function (params) {
            return this.fragmentsDomain.bulkReadFragments(params);
        };
        APIService.prototype.bulkReadFragments2 = function (params) {
            return this.fragmentsDomain.bulkReadFragments2(params);
        };
        APIService.prototype.bulkReadPublishedFragments = function (params) {
            return this.fragmentsDomain.bulkReadPublishedFragments(params);
        };
        APIService.prototype.bulkReadPublishedFragments2 = function (params) {
            return this.fragmentsDomain.bulkReadPublishedFragments2(params);
        };
        APIService.prototype.createFragment = function () {
            return this.fragmentsDomain.createFragment();
        };
        APIService.prototype.deleteFragment = function (fragmentId) {
            return this.fragmentsDomain.deleteFragment(fragmentId);
        };
        APIService.prototype.mergeFragment = function (fragmentId) {
            return this.fragmentsDomain.mergeFragment(fragmentId);
        };
        APIService.prototype.publishFragment = function (fragmentId) {
            return this.fragmentsDomain.publishFragment(fragmentId);
        };
        APIService.prototype.readFragment = function (fragmentId) {
            return this.fragmentsDomain.readFragment(fragmentId);
        };
        APIService.prototype.readFragment2 = function (fragmentId) {
            return this.fragmentsDomain.readFragment2(fragmentId);
        };
        APIService.prototype.readFragmentDiff = function (fragmentId) {
            return this.fragmentsDomain.readFragmentDiff(fragmentId);
        };
        APIService.prototype.readFragmentDiff2 = function (fragmentId) {
            return this.fragmentsDomain.readFragmentDiff2(fragmentId);
        };
        APIService.prototype.readFragmentSample = function (fragmentId) {
            return this.fragmentsDomain.readFragmentSample(fragmentId);
        };
        APIService.prototype.readFragmentSample2 = function (fragmentId) {
            return this.fragmentsDomain.readFragmentSample2(fragmentId);
        };
        APIService.prototype.updateFragment = function (fragmentId, body) {
            return this.fragmentsDomain.updateFragment(fragmentId, body);
        };
        Object.defineProperty(APIService.prototype, "geometriesDomain", {
            get: function () {
                if (!this._geometriesDomain) {
                    this._geometriesDomain = this.injector.get(GeometriesDomain);
                }
                return this._geometriesDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadGeometries = function (params) {
            return this.geometriesDomain.bulkReadGeometries(params);
        };
        APIService.prototype.bulkReadGeometries2 = function (params) {
            return this.geometriesDomain.bulkReadGeometries2(params);
        };
        APIService.prototype.bulkUpdateGeometries = function (body) {
            return this.geometriesDomain.bulkUpdateGeometries(body);
        };
        APIService.prototype.readGeometryByCard = function (cardId) {
            return this.geometriesDomain.readGeometryByCard(cardId);
        };
        APIService.prototype.readGeometryByCard2 = function (cardId) {
            return this.geometriesDomain.readGeometryByCard2(cardId);
        };
        APIService.prototype.readGraph = function (params) {
            return this.geometriesDomain.readGraph(params);
        };
        APIService.prototype.readGraph2 = function (params) {
            return this.geometriesDomain.readGraph2(params);
        };
        Object.defineProperty(APIService.prototype, "gossipDomain", {
            get: function () {
                if (!this._gossipDomain) {
                    this._gossipDomain = this.injector.get(GossipDomain);
                }
                return this._gossipDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadSpeechLanguages = function () {
            return this.gossipDomain.bulkReadSpeechLanguages();
        };
        APIService.prototype.bulkReadSpeechLanguages2 = function () {
            return this.gossipDomain.bulkReadSpeechLanguages2();
        };
        APIService.prototype.bulkReadTextLanguages = function () {
            return this.gossipDomain.bulkReadTextLanguages();
        };
        APIService.prototype.bulkReadTextLanguages2 = function () {
            return this.gossipDomain.bulkReadTextLanguages2();
        };
        APIService.prototype.detectSpeechLanguages = function (body) {
            return this.gossipDomain.detectSpeechLanguages(body);
        };
        APIService.prototype.detectTextLanguages = function (body) {
            return this.gossipDomain.detectTextLanguages(body);
        };
        Object.defineProperty(APIService.prototype, "hashtagsDomain", {
            get: function () {
                if (!this._hashtagsDomain) {
                    this._hashtagsDomain = this.injector.get(HashtagsDomain);
                }
                return this._hashtagsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadHashtags = function (params) {
            return this.hashtagsDomain.bulkReadHashtags(params);
        };
        APIService.prototype.bulkReadHashtags2 = function (params) {
            return this.hashtagsDomain.bulkReadHashtags2(params);
        };
        APIService.prototype.createHashtag = function (body) {
            return this.hashtagsDomain.createHashtag(body);
        };
        APIService.prototype.deleteHashtag = function (hashtagId, params) {
            return this.hashtagsDomain.deleteHashtag(hashtagId, params);
        };
        APIService.prototype.readHashtagsToc = function (params) {
            return this.hashtagsDomain.readHashtagsToc(params);
        };
        APIService.prototype.readHashtagsToc2 = function (params) {
            return this.hashtagsDomain.readHashtagsToc2(params);
        };
        APIService.prototype.updateHashtag = function (hashtagId, body) {
            return this.hashtagsDomain.updateHashtag(hashtagId, body);
        };
        Object.defineProperty(APIService.prototype, "invoicesDomain", {
            get: function () {
                if (!this._invoicesDomain) {
                    this._invoicesDomain = this.injector.get(InvoicesDomain);
                }
                return this._invoicesDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadInvoices = function () {
            return this.invoicesDomain.bulkReadInvoices();
        };
        APIService.prototype.bulkReadInvoices2 = function () {
            return this.invoicesDomain.bulkReadInvoices2();
        };
        APIService.prototype.calculateDebt = function () {
            return this.invoicesDomain.calculateDebt();
        };
        APIService.prototype.calculateDebt2 = function () {
            return this.invoicesDomain.calculateDebt2();
        };
        Object.defineProperty(APIService.prototype, "linksDomain", {
            get: function () {
                if (!this._linksDomain) {
                    this._linksDomain = this.injector.get(LinksDomain);
                }
                return this._linksDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.deleteLink = function (fromCardId, toCardId) {
            return this.linksDomain.deleteLink(fromCardId, toCardId);
        };
        APIService.prototype.readOrCreateLink = function (body) {
            return this.linksDomain.readOrCreateLink(body);
        };
        Object.defineProperty(APIService.prototype, "mediaitemsDomain", {
            get: function () {
                if (!this._mediaitemsDomain) {
                    this._mediaitemsDomain = this.injector.get(MediaitemsDomain);
                }
                return this._mediaitemsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadMediaitems = function (params) {
            return this.mediaitemsDomain.bulkReadMediaitems(params);
        };
        APIService.prototype.bulkReadMediaitems2 = function (params) {
            return this.mediaitemsDomain.bulkReadMediaitems2(params);
        };
        APIService.prototype.deleteMediaitem = function (mediaitemId, params) {
            return this.mediaitemsDomain.deleteMediaitem(mediaitemId, params);
        };
        APIService.prototype.readMediaitem = function (mediaitemId) {
            return this.mediaitemsDomain.readMediaitem(mediaitemId);
        };
        APIService.prototype.readMediaitem2 = function (mediaitemId) {
            return this.mediaitemsDomain.readMediaitem2(mediaitemId);
        };
        APIService.prototype.readMediaitemByProcessId = function () {
            return this.mediaitemsDomain.readMediaitemByProcessId();
        };
        APIService.prototype.readMediaitemByProcessId2 = function () {
            return this.mediaitemsDomain.readMediaitemByProcessId2();
        };
        APIService.prototype.readOrCreateMediaitem = function (body) {
            return this.mediaitemsDomain.readOrCreateMediaitem(body);
        };
        APIService.prototype.updateMediaitem = function (mediaitemId, body) {
            return this.mediaitemsDomain.updateMediaitem(mediaitemId, body);
        };
        APIService.prototype.updateMediaitemRepresentation = function (mediaitemId, body) {
            return this.mediaitemsDomain.updateMediaitemRepresentation(mediaitemId, body);
        };
        Object.defineProperty(APIService.prototype, "notificationsDomain", {
            get: function () {
                if (!this._notificationsDomain) {
                    this._notificationsDomain = this.injector.get(NotificationsDomain);
                }
                return this._notificationsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.acknowledgeNotification = function (notificationId) {
            return this.notificationsDomain.acknowledgeNotification(notificationId);
        };
        APIService.prototype.bulkReadNotifications = function (params) {
            return this.notificationsDomain.bulkReadNotifications(params);
        };
        APIService.prototype.bulkReadNotifications2 = function (params) {
            return this.notificationsDomain.bulkReadNotifications2(params);
        };
        Object.defineProperty(APIService.prototype, "nounsDomain", {
            get: function () {
                if (!this._nounsDomain) {
                    this._nounsDomain = this.injector.get(NounsDomain);
                }
                return this._nounsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadIcons = function (params) {
            return this.nounsDomain.bulkReadIcons(params);
        };
        APIService.prototype.bulkReadIcons2 = function (params) {
            return this.nounsDomain.bulkReadIcons2(params);
        };
        Object.defineProperty(APIService.prototype, "pathsDomain", {
            get: function () {
                if (!this._pathsDomain) {
                    this._pathsDomain = this.injector.get(PathsDomain);
                }
                return this._pathsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkDeletePaths = function (params) {
            return this.pathsDomain.bulkDeletePaths(params);
        };
        APIService.prototype.bulkReadPaths = function (params) {
            return this.pathsDomain.bulkReadPaths(params);
        };
        APIService.prototype.bulkReadPaths2 = function (params) {
            return this.pathsDomain.bulkReadPaths2(params);
        };
        APIService.prototype.createPath = function (body) {
            return this.pathsDomain.createPath(body);
        };
        APIService.prototype.readPath = function (pathId) {
            return this.pathsDomain.readPath(pathId);
        };
        APIService.prototype.readPath2 = function (pathId) {
            return this.pathsDomain.readPath2(pathId);
        };
        APIService.prototype.updatePath = function (pathId, body) {
            return this.pathsDomain.updatePath(pathId, body);
        };
        Object.defineProperty(APIService.prototype, "payment_cardsDomain", {
            get: function () {
                if (!this._payment_cardsDomain) {
                    this._payment_cardsDomain = this.injector.get(PaymentCardsDomain);
                }
                return this._payment_cardsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.asDefaultMarkPaymentcard = function (paymentCardId) {
            return this.payment_cardsDomain.asDefaultMarkPaymentcard(paymentCardId);
        };
        APIService.prototype.bulkReadPaymentcards = function () {
            return this.payment_cardsDomain.bulkReadPaymentcards();
        };
        APIService.prototype.bulkReadPaymentcards2 = function () {
            return this.payment_cardsDomain.bulkReadPaymentcards2();
        };
        APIService.prototype.createPaymentcard = function (body) {
            return this.payment_cardsDomain.createPaymentcard(body);
        };
        APIService.prototype.deletePaymentcard = function (paymentCardId) {
            return this.payment_cardsDomain.deletePaymentcard(paymentCardId);
        };
        APIService.prototype.payWithDefaultPaymentCard = function (body) {
            return this.payment_cardsDomain.payWithDefaultPaymentCard(body);
        };
        APIService.prototype.renderPaymentCardWidget = function () {
            return this.payment_cardsDomain.renderPaymentCardWidget();
        };
        APIService.prototype.renderPaymentCardWidget2 = function () {
            return this.payment_cardsDomain.renderPaymentCardWidget2();
        };
        Object.defineProperty(APIService.prototype, "paymentsDomain", {
            get: function () {
                if (!this._paymentsDomain) {
                    this._paymentsDomain = this.injector.get(PaymentsDomain);
                }
                return this._paymentsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.updatePaymentStatus = function (body) {
            return this.paymentsDomain.updatePaymentStatus(body);
        };
        Object.defineProperty(APIService.prototype, "processesDomain", {
            get: function () {
                if (!this._processesDomain) {
                    this._processesDomain = this.injector.get(ProcessesDomain);
                }
                return this._processesDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.createDeletionProcess = function (body) {
            return this.processesDomain.createDeletionProcess(body);
        };
        APIService.prototype.createDownloadProcess = function (body) {
            return this.processesDomain.createDownloadProcess(body);
        };
        APIService.prototype.createMediaLock = function (body) {
            return this.processesDomain.createMediaLock(body);
        };
        APIService.prototype.createUploadProcess = function (body) {
            return this.processesDomain.createUploadProcess(body);
        };
        APIService.prototype.readInvariants = function (params) {
            return this.processesDomain.readInvariants(params);
        };
        APIService.prototype.readInvariants2 = function (params) {
            return this.processesDomain.readInvariants2(params);
        };
        APIService.prototype.readProcessState = function (params) {
            return this.processesDomain.readProcessState(params);
        };
        APIService.prototype.readProcessState2 = function (params) {
            return this.processesDomain.readProcessState2(params);
        };
        APIService.prototype.signProcess = function (params) {
            return this.processesDomain.signProcess(params);
        };
        APIService.prototype.signProcess2 = function (params) {
            return this.processesDomain.signProcess2(params);
        };
        APIService.prototype.watchConversionStatus = function (waiterId, params) {
            return this.processesDomain.watchConversionStatus(waiterId, params);
        };
        APIService.prototype.watchConversionStatus2 = function (waiterId, params) {
            return this.processesDomain.watchConversionStatus2(waiterId, params);
        };
        Object.defineProperty(APIService.prototype, "quizzerDomain", {
            get: function () {
                if (!this._quizzerDomain) {
                    this._quizzerDomain = this.injector.get(QuizzerDomain);
                }
                return this._quizzerDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadQuizattempts = function (quizId) {
            return this.quizzerDomain.bulkReadQuizattempts(quizId);
        };
        APIService.prototype.bulkReadQuizattempts2 = function (quizId) {
            return this.quizzerDomain.bulkReadQuizattempts2(quizId);
        };
        APIService.prototype.bulkReadQuizzes = function () {
            return this.quizzerDomain.bulkReadQuizzes();
        };
        APIService.prototype.bulkReadQuizzes2 = function () {
            return this.quizzerDomain.bulkReadQuizzes2();
        };
        APIService.prototype.createQuiz = function (body) {
            return this.quizzerDomain.createQuiz(body);
        };
        APIService.prototype.createQuizattempt = function (quizId, body) {
            return this.quizzerDomain.createQuizattempt(quizId, body);
        };
        APIService.prototype.deleteQuiz = function (quizId) {
            return this.quizzerDomain.deleteQuiz(quizId);
        };
        APIService.prototype.readQuiz = function (quizId) {
            return this.quizzerDomain.readQuiz(quizId);
        };
        APIService.prototype.readQuiz2 = function (quizId) {
            return this.quizzerDomain.readQuiz2(quizId);
        };
        APIService.prototype.updateQuiz = function (quizId, body) {
            return this.quizzerDomain.updateQuiz(quizId, body);
        };
        Object.defineProperty(APIService.prototype, "recallDomain", {
            get: function () {
                if (!this._recallDomain) {
                    this._recallDomain = this.injector.get(RecallDomain);
                }
                return this._recallDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.createRecallSession = function (body) {
            return this.recallDomain.createRecallSession(body);
        };
        APIService.prototype.readRecallSummary = function () {
            return this.recallDomain.readRecallSummary();
        };
        APIService.prototype.readRecallSummary2 = function () {
            return this.recallDomain.readRecallSummary2();
        };
        Object.defineProperty(APIService.prototype, "subscriptionsDomain", {
            get: function () {
                if (!this._subscriptionsDomain) {
                    this._subscriptionsDomain = this.injector.get(SubscriptionsDomain);
                }
                return this._subscriptionsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.changeSubscription = function (body) {
            return this.subscriptionsDomain.changeSubscription(body);
        };
        Object.defineProperty(APIService.prototype, "tasksDomain", {
            get: function () {
                if (!this._tasksDomain) {
                    this._tasksDomain = this.injector.get(TasksDomain);
                }
                return this._tasksDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadTasks = function (params) {
            return this.tasksDomain.bulkReadTasks(params);
        };
        APIService.prototype.bulkReadTasks2 = function (params) {
            return this.tasksDomain.bulkReadTasks2(params);
        };
        APIService.prototype.bulkReadTaskBins = function (params) {
            return this.tasksDomain.bulkReadTaskBins(params);
        };
        APIService.prototype.bulkReadTaskBins2 = function (params) {
            return this.tasksDomain.bulkReadTaskBins2(params);
        };
        Object.defineProperty(APIService.prototype, "wordsDomain", {
            get: function () {
                if (!this._wordsDomain) {
                    this._wordsDomain = this.injector.get(WordsDomain);
                }
                return this._wordsDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.bulkReadWords = function (params) {
            return this.wordsDomain.bulkReadWords(params);
        };
        APIService.prototype.bulkReadWords2 = function (params) {
            return this.wordsDomain.bulkReadWords2(params);
        };
        APIService.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        APIService.ctorParameters = function () {
            return [
                { type: i0.Injector }
            ];
        };
        return APIService;
    }());

    /**
    * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
    * OVERWRITTEN
    */
    var CoSphereClientModule = (function () {
        function CoSphereClientModule() {
        }
        CoSphereClientModule.forRoot = function (config) {
            return {
                ngModule: CoSphereClientModule,
                providers: [
                    { provide: 'config', useValue: config }
                ]
            };
        };
        CoSphereClientModule.decorators = [
            { type: i0.NgModule, args: [{
                        imports: [i1.HttpClientModule],
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
        return CoSphereClientModule;
    }());

    /**
     * Generated bundle index. Do not edit.
     */

    exports.CoSphereClientModule = CoSphereClientModule;
    exports.ClientService = ClientService;
    exports.APIService = APIService;
    exports.AccountSettingsDomain = AccountSettingsDomain;
    exports.AccountsDomain = AccountsDomain;
    exports.AttemptStatsDomain = AttemptStatsDomain;
    exports.AttemptsDomain = AttemptsDomain;
    exports.AuthTokensDomain = AuthTokensDomain;
    exports.BricksDomain = BricksDomain;
    exports.CardsDomain = CardsDomain;
    exports.CategoriesDomain = CategoriesDomain;
    exports.ContactsDomain = ContactsDomain;
    exports.DonationsDomain = DonationsDomain;
    exports.ExternalAppsDomain = ExternalAppsDomain;
    exports.FocusRecordsDomain = FocusRecordsDomain;
    exports.FragmentHashtagsDomain = FragmentHashtagsDomain;
    exports.FragmentWordsDomain = FragmentWordsDomain;
    exports.FragmentsDomain = FragmentsDomain;
    exports.GeometriesDomain = GeometriesDomain;
    exports.GossipDomain = GossipDomain;
    exports.HashtagsDomain = HashtagsDomain;
    exports.InvoicesDomain = InvoicesDomain;
    exports.LinksDomain = LinksDomain;
    exports.MediaitemsDomain = MediaitemsDomain;
    exports.NotificationsDomain = NotificationsDomain;
    exports.NounsDomain = NounsDomain;
    exports.PathsDomain = PathsDomain;
    exports.PaymentCardsDomain = PaymentCardsDomain;
    exports.PaymentsDomain = PaymentsDomain;
    exports.ProcessesDomain = ProcessesDomain;
    exports.QuizzerDomain = QuizzerDomain;
    exports.RecallDomain = RecallDomain;
    exports.SubscriptionsDomain = SubscriptionsDomain;
    exports.TasksDomain = TasksDomain;
    exports.WordsDomain = WordsDomain;

    Object.defineProperty(exports, '__esModule', { value: true });

})));

//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29zcGhlcmUtY2xpZW50LnVtZC5qcy5tYXAiLCJzb3VyY2VzIjpbIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9zZXJ2aWNlcy9jbGllbnQuc2VydmljZS50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2FjY291bnRfc2V0dGluZ3MvYWNjb3VudF9zZXR0aW5ncy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hY2NvdW50cy9hY2NvdW50cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hY2NvdW50cy9hY2NvdW50cy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hdHRlbXB0X3N0YXRzL2F0dGVtcHRfc3RhdHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvYXR0ZW1wdHMvYXR0ZW1wdHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvYXV0aF90b2tlbnMvYXV0aF90b2tlbnMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvYnJpY2tzL2JyaWNrcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9icmlja3MvYnJpY2tzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2NhcmRzL2NhcmRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2NhdGVnb3JpZXMvY2F0ZWdvcmllcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9jYXRlZ29yaWVzL2NhdGVnb3JpZXMubW9kZWxzLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvY29udGFjdHMvY29udGFjdHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZG9uYXRpb25zL2RvbmF0aW9ucy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9kb25hdGlvbnMvZG9uYXRpb25zLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2V4dGVybmFsX2FwcHMvZXh0ZXJuYWxfYXBwcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9mb2N1c19yZWNvcmRzL2ZvY3VzX3JlY29yZHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZnJhZ21lbnRfaGFzaHRhZ3MvZnJhZ21lbnRfaGFzaHRhZ3MuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZnJhZ21lbnRfd29yZHMvZnJhZ21lbnRfd29yZHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZnJhZ21lbnRzL2ZyYWdtZW50cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9nZW9tZXRyaWVzL2dlb21ldHJpZXMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZ29zc2lwL2dvc3NpcC5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9oYXNodGFncy9oYXNodGFncy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9pbnZvaWNlcy9pbnZvaWNlcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9pbnZvaWNlcy9pbnZvaWNlcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9saW5rcy9saW5rcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9saW5rcy9saW5rcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9tZWRpYWl0ZW1zL21lZGlhaXRlbXMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvbm90aWZpY2F0aW9ucy9ub3RpZmljYXRpb25zLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL25vdGlmaWNhdGlvbnMvbm90aWZpY2F0aW9ucy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9ub3Vucy9ub3Vucy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9wYXRocy9wYXRocy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9wYXltZW50X2NhcmRzL3BheW1lbnRfY2FyZHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcGF5bWVudF9jYXJkcy9wYXltZW50X2NhcmRzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3BheW1lbnRzL3BheW1lbnRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3Byb2Nlc3Nlcy9wcm9jZXNzZXMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcXVpenplci9xdWl6emVyLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3JlY2FsbC9yZWNhbGwuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvc3Vic2NyaXB0aW9ucy9zdWJzY3JpcHRpb25zLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3N1YnNjcmlwdGlvbnMvc3Vic2NyaXB0aW9ucy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy90YXNrcy90YXNrcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy90YXNrcy90YXNrcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy93b3Jkcy93b3Jkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvc2VydmljZXMvYXBpLnNlcnZpY2UudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvY29zcGhlcmUtY2xpZW50Lm1vZHVsZS50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9jb3NwaGVyZS1jbGllbnQudHMiXSwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgSW5qZWN0IH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQge1xuICBIdHRwQ2xpZW50LFxuICBIdHRwUGFyYW1zLFxuICBIdHRwSGVhZGVycyxcbiAgSHR0cEVycm9yUmVzcG9uc2Vcbn0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgQmVoYXZpb3JTdWJqZWN0LCBTdWJqZWN0LCBPYnNlcnZhYmxlLCB0aHJvd0Vycm9yIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgeyBjYXRjaEVycm9yLCByZXRyeSwgbWFwIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ29uZmlnIH0gZnJvbSAnLi9jb25maWcuc2VydmljZSc7XG5pbXBvcnQgeyBPcHRpb25zLCBTdGF0ZSwgRGF0YVN0YXRlLCBSZXF1ZXN0U3RhdGUgfSBmcm9tICcuL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5ASW5qZWN0YWJsZSh7XG4gIHByb3ZpZGVkSW46ICdyb290J1xufSlcbmV4cG9ydCBjbGFzcyBDbGllbnRTZXJ2aWNlIHtcbiAgLyoqXG4gICAqIFN0YXRlIGZvciBhbGwgR0VUIHBheWxvYWRzXG4gICAqL1xuICBzdGF0ZSA9IG5ldyBNYXA8c3RyaW5nLCBTdGF0ZTxhbnk+PigpO1xuXG4gIHJlYWRvbmx5IGJhc2VVcmw6IHN0cmluZztcbiAgcmVhZG9ubHkgYXV0aFRva2VuOiBzdHJpbmc7XG5cbiAgcHJpdmF0ZSByZWFkb25seSBkZWZhdWx0QXV0aFRva2VuOiBzdHJpbmcgPSAnYXV0aF90b2tlbic7XG5cbiAgLyoqXG4gICAqIENhY2hlIHRpbWUgLSBldmVyeSBHRVQgcmVxdWVzdCBpcyB0YWtlbiBvbmx5IGlmIHRoZSBsYXN0IG9uZVxuICAgKiB3YXMgaW52b2tlZCBub3QgZWFybGllciB0aGVuIGBjYWNoZVRpbWVgIG1pbnMgYWdvLlxuICAgKiBPbmx5IHN1Y2Nlc3NmdWwgcmVzcG9uc2VzIGFyZSBjYWNoZWQgKDJ4eClcbiAgICovXG4gIHByaXZhdGUgcmVhZG9ubHkgY2FjaGVUaW1lID0gMTAwMCAqIDYwICogNjA7IC8vIDYwIG1pbnNcblxuICBjb25zdHJ1Y3RvcihASW5qZWN0KCdjb25maWcnKSBwcml2YXRlIGNvbmZpZzogQ29uZmlnLCBwcml2YXRlIGh0dHA6IEh0dHBDbGllbnQpIHtcbiAgICB0aGlzLmJhc2VVcmwgPSB0aGlzLmNvbmZpZy5iYXNlVXJsO1xuICAgIHRoaXMuYXV0aFRva2VuID1cbiAgICAgIHRoaXMuY29uZmlnLmF1dGhUb2tlbiB8fCB0aGlzLmRlZmF1bHRBdXRoVG9rZW47XG4gIH1cblxuICBnZXQ8VD4oZW5kcG9pbnQ6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiBPYnNlcnZhYmxlPFQ+IHtcbiAgICBjb25zdCB1cmwgPSB0aGlzLmdldFVybChlbmRwb2ludCk7XG4gICAgY29uc3QgaHR0cE9wdGlvbnMgPSB0aGlzLmdldEh0dHBPcHRpb25zKG9wdGlvbnMpO1xuICAgIHJldHVybiB0aGlzLmh0dHBcbiAgICAgIC5nZXQodXJsLCBodHRwT3B0aW9ucylcbiAgICAgIC5waXBlKHJldHJ5KDMpLCBjYXRjaEVycm9yKHRoaXMuaGFuZGxlRXJyb3IpKSBhcyBPYnNlcnZhYmxlPFQ+O1xuICB9XG5cbiAgcG9zdDxUPihlbmRwb2ludDogc3RyaW5nLCBib2R5OiBhbnksIG9wdGlvbnM/OiBPcHRpb25zKTogT2JzZXJ2YWJsZTxUPiB7XG4gICAgY29uc3QgdXJsID0gdGhpcy5nZXRVcmwoZW5kcG9pbnQpO1xuICAgIGNvbnN0IGh0dHBPcHRpb25zID0gdGhpcy5nZXRIdHRwT3B0aW9ucyhvcHRpb25zKTtcbiAgICByZXR1cm4gdGhpcy5odHRwXG4gICAgICAucG9zdCh1cmwsIGJvZHksIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBwdXQ8VD4oZW5kcG9pbnQ6IHN0cmluZywgYm9keTogYW55LCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLnB1dCh1cmwsIGJvZHksIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBkZWxldGU8VD4oZW5kcG9pbnQ6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiBPYnNlcnZhYmxlPFQ+IHtcbiAgICBjb25zdCB1cmwgPSB0aGlzLmdldFVybChlbmRwb2ludCk7XG4gICAgY29uc3QgaHR0cE9wdGlvbnMgPSB0aGlzLmdldEh0dHBPcHRpb25zKG9wdGlvbnMpO1xuICAgIHJldHVybiB0aGlzLmh0dHBcbiAgICAgIC5kZWxldGUodXJsLCBodHRwT3B0aW9ucylcbiAgICAgIC5waXBlKHJldHJ5KDMpLCBjYXRjaEVycm9yKHRoaXMuaGFuZGxlRXJyb3IpKSBhcyBPYnNlcnZhYmxlPFQ+O1xuICB9XG5cbiAgZ2V0RGF0YVN0YXRlPFQ+KGVuZHBvaW50OiBzdHJpbmcsIG9wdGlvbnM/OiBPcHRpb25zKTogRGF0YVN0YXRlPFQ+IHtcbiAgICBjb25zdCBrZXkgPSBvcHRpb25zICYmIG9wdGlvbnMucGFyYW1zID8gYCR7ZW5kcG9pbnR9XyR7SlNPTi5zdHJpbmdpZnkob3B0aW9ucy5wYXJhbXMpfWAgOiBlbmRwb2ludDtcbiAgICB0aGlzLmluaXRTdGF0ZShrZXksIG9wdGlvbnMpO1xuXG4gICAgbGV0IGNhY2hlID0gdHJ1ZTtcbiAgICBsZXQgcGFyYW1zOiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG5cbiAgICBpZiAoXy5oYXMob3B0aW9ucywgJ2NhY2hlJykpIHtcbiAgICAgIGNhY2hlID0gb3B0aW9ucy5jYWNoZTtcbiAgICB9XG5cbiAgICBpZiAoXy5oYXMob3B0aW9ucywgJ3BhcmFtcycpKSB7XG4gICAgICBwYXJhbXMgPSBvcHRpb25zLnBhcmFtcztcbiAgICB9XG5cbiAgICAvLyBHZXQgdGhlIGVuZHBvaW50IHN0YXRlXG4gICAgY29uc3Qgc3RhdGUgPSB0aGlzLnN0YXRlLmdldChrZXkpO1xuXG4gICAgLy8gRG8gbm90IGFsbG93IGludm9rZSB0aGUgc2FtZSBHRVQgcmVxdWVzdCB3aGlsZSBvbmUgaXMgcGVuZGluZ1xuICAgIGlmIChzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyAvKiYmICFfLmlzRW1wdHkocGFyYW1zKSovKSB7XG4gICAgICByZXR1cm4gc3RhdGUuZGF0YVN0YXRlO1xuICAgIH1cblxuICAgIGNvbnN0IGN1cnJlbnRUaW1lID0gK25ldyBEYXRlKCk7XG4gICAgaWYgKFxuICAgICAgY3VycmVudFRpbWUgLSBzdGF0ZS5yZXF1ZXN0U3RhdGUuY2FjaGVkQXQgPiB0aGlzLmNhY2hlVGltZSB8fFxuICAgICAgLy8gIV8uaXNFbXB0eShwYXJhbXMpIHx8XG4gICAgICAhY2FjaGVcbiAgICApIHtcbiAgICAgIHN0YXRlLnJlcXVlc3RTdGF0ZS5wZW5kaW5nID0gdHJ1ZTtcbiAgICAgIHRoaXMuZ2V0KGVuZHBvaW50LCBvcHRpb25zKVxuICAgICAgICAucGlwZShcbiAgICAgICAgICBtYXAoZGF0YSA9PiAob3B0aW9ucy5yZXNwb25zZU1hcCA/IGRhdGFbb3B0aW9ucy5yZXNwb25zZU1hcF0gOiBkYXRhKSlcbiAgICAgICAgKVxuICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgIGRhdGEgPT4ge1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmRhdGEkLm5leHQoZGF0YSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuaXNEYXRhJC5uZXh0KCFfLmlzRW1wdHkoZGF0YSkpO1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQoZmFsc2UpO1xuICAgICAgICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLnBlbmRpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIHN0YXRlLnJlcXVlc3RTdGF0ZS5jYWNoZWRBdCA9IGN1cnJlbnRUaW1lO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIHN0YXRlLmRhdGFTdGF0ZS5pc0RhdGEkLm5leHQoZmFsc2UpO1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmRhdGEkLmVycm9yKG51bGwpO1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQoZmFsc2UpO1xuICAgICAgICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLnBlbmRpbmcgPSBmYWxzZTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0YXRlLmRhdGFTdGF0ZS5sb2FkaW5nJC5uZXh0KGZhbHNlKTtcbiAgICB9XG5cbiAgICByZXR1cm4gc3RhdGUuZGF0YVN0YXRlO1xuICB9XG5cbiAgcHJpdmF0ZSBpbml0U3RhdGUoa2V5OiBzdHJpbmcsIG9wdGlvbnM/OiBPcHRpb25zKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLnN0YXRlLmhhcyhrZXkpKSB7XG4gICAgICB0aGlzLnN0YXRlLnNldChrZXksIHtcbiAgICAgICAgZGF0YVN0YXRlOiB7XG4gICAgICAgICAgbG9hZGluZyQ6IG5ldyBCZWhhdmlvclN1YmplY3QodHJ1ZSksXG4gICAgICAgICAgaXNEYXRhJDogbmV3IEJlaGF2aW9yU3ViamVjdChmYWxzZSksXG4gICAgICAgICAgZGF0YSQ6IG5ldyBCZWhhdmlvclN1YmplY3QobnVsbClcbiAgICAgICAgfSxcbiAgICAgICAgcmVxdWVzdFN0YXRlOiB7XG4gICAgICAgICAgY2FjaGVkQXQ6IDAsXG4gICAgICAgICAgcGVuZGluZzogZmFsc2VcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuc3RhdGUuZ2V0KGtleSkuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQodHJ1ZSk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBnZXRIdHRwT3B0aW9ucyhcbiAgICBvcHRpb25zPzogT3B0aW9uc1xuICApOiB7XG4gICAgcGFyYW1zPzogSHR0cFBhcmFtcyB8IHsgW3BhcmFtOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgIGhlYWRlcnM/OiBIdHRwSGVhZGVycyB8IHsgW2hlYWRlcjogc3RyaW5nXTogc3RyaW5nIHwgc3RyaW5nW10gfTtcbiAgICByZXBvcnRQcm9ncmVzcz86IGJvb2xlYW47XG4gIH0ge1xuICAgIGNvbnN0IGF1dGhvcml6YXRpb25SZXF1aXJlZCA9IF8uaGFzKG9wdGlvbnMsICdhdXRob3JpemF0aW9uUmVxdWlyZWQnKVxuICAgICAgPyBvcHRpb25zLmF1dGhvcml6YXRpb25SZXF1aXJlZFxuICAgICAgOiB0cnVlO1xuICAgIGNvbnN0IGV0YWcgPSAob3B0aW9ucyAmJiBvcHRpb25zLmV0YWcpIHx8IHVuZGVmaW5lZDtcblxuICAgIGxldCBodHRwT3B0aW9uczoge1xuICAgICAgcGFyYW1zPzogSHR0cFBhcmFtcyB8IHsgW3BhcmFtOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgICAgaGVhZGVycz86IEh0dHBIZWFkZXJzIHwgeyBbaGVhZGVyOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgICAgcmVwb3J0UHJvZ3Jlc3M/OiBib29sZWFuO1xuICAgIH0gPSB7XG4gICAgICBoZWFkZXJzOiB0aGlzLmdldEhlYWRlcnMoYXV0aG9yaXphdGlvblJlcXVpcmVkLCBldGFnKVxuICAgIH07XG5cbiAgICBpZiAoXy5oYXMob3B0aW9ucywgJ2hlYWRlcnMnKSkge1xuICAgICAgLy8gdHNsaW50OmRpc2FibGVcbiAgICAgIGZvciAobGV0IGtleSBpbiBvcHRpb25zLmhlYWRlcnMpIHtcbiAgICAgICAgaHR0cE9wdGlvbnMuaGVhZGVyc1trZXldID0gKDxhbnk+b3B0aW9ucykuaGVhZGVyc1trZXldO1xuICAgICAgfVxuICAgICAgLy8gdHNsaW50OmVuYWJsZVxuICAgIH1cblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAncGFyYW1zJykpIHtcbiAgICAgIGh0dHBPcHRpb25zLnBhcmFtcyA9IG9wdGlvbnMucGFyYW1zO1xuICAgIH1cblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAncmVwb3J0UHJvZ3Jlc3MnKSkge1xuICAgICAgaHR0cE9wdGlvbnMucmVwb3J0UHJvZ3Jlc3MgPSBvcHRpb25zLnJlcG9ydFByb2dyZXNzO1xuICAgIH1cblxuICAgIHJldHVybiBodHRwT3B0aW9ucztcbiAgfVxuXG4gIHByaXZhdGUgZ2V0SGVhZGVycyhcbiAgICBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGJvb2xlYW4sXG4gICAgZXRhZz86IHN0cmluZ1xuICApOiB7IFtrZXk6IHN0cmluZ106IHN0cmluZyB9IHtcbiAgICBsZXQgaGVhZGVycyA9IHtcbiAgICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbidcbiAgICB9O1xuXG4gICAgaWYgKGF1dGhvcml6YXRpb25SZXF1aXJlZCkge1xuICAgICAgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gYEJlYXJlciAke3RoaXMuZ2V0VG9rZW4oKX1gO1xuICAgIH1cblxuICAgIGlmIChldGFnKSB7XG4gICAgICBoZWFkZXJzWydFVGFnJ10gPSBldGFnO1xuICAgIH1cblxuICAgIHJldHVybiBoZWFkZXJzO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRVcmwoZW5kcG9pbnQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGAke3RoaXMuYmFzZVVybH0ke2VuZHBvaW50fWA7XG4gIH1cblxuICBwcml2YXRlIGdldFRva2VuKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKHRoaXMuYXV0aFRva2VuKTtcbiAgfVxuXG4gIHByaXZhdGUgaGFuZGxlRXJyb3IoZXJyb3I6IEh0dHBFcnJvclJlc3BvbnNlKSB7XG4gICAgaWYgKGVycm9yLmVycm9yIGluc3RhbmNlb2YgRXJyb3JFdmVudCkge1xuICAgICAgLy8gQSBjbGllbnQtc2lkZSBvciBuZXR3b3JrIGVycm9yIG9jY3VycmVkLiBIYW5kbGUgaXQgYWNjb3JkaW5nbHkuXG4gICAgICBjb25zb2xlLmVycm9yKCdBbiBlcnJvciBvY2N1cnJlZDonLCBlcnJvci5lcnJvci5tZXNzYWdlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gVGhlIGJhY2tlbmQgcmV0dXJuZWQgYW4gdW5zdWNjZXNzZnVsIHJlc3BvbnNlIGNvZGUuXG4gICAgICAvLyBUaGUgcmVzcG9uc2UgYm9keSBtYXkgY29udGFpbiBjbHVlcyBhcyB0byB3aGF0IHdlbnQgd3JvbmcsXG4gICAgICBjb25zb2xlLmVycm9yKFxuICAgICAgICBgQmFja2VuZCByZXR1cm5lZCBjb2RlICR7ZXJyb3Iuc3RhdHVzfSwgYCArIGBib2R5IHdhczogJHtlcnJvci5lcnJvcn1gXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIHJldHVybiBhbiBvYnNlcnZhYmxlIHdpdGggYSB1c2VyLWZhY2luZyBlcnJvciBtZXNzYWdlXG4gICAgcmV0dXJuIHRocm93RXJyb3IoJ1NvbWV0aGluZyBiYWQgaGFwcGVuZWQ7IHBsZWFzZSB0cnkgYWdhaW4gbGF0ZXIuJyk7XG4gIH1cbn1cbiIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQWNjb3VudCBTZXR0aW5ncyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hY2NvdW50X3NldHRpbmdzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBY2NvdW50U2V0dGluZ3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBBY2NvdW50IFNldHRpbmdzXG4gICAgICovXG4gICAgcHVibGljIHJlYWRBY2NvdW50c2V0dGluZygpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEFjY291bnRzZXR0aW5nUmVzcG9uc2U+KCcvYWNjb3VudC9zZXR0aW5ncy8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRBY2NvdW50c2V0dGluZzIoKTogT2JzZXJ2YWJsZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4oJy9hY2NvdW50L3NldHRpbmdzLycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBBY2NvdW50IFNldHRpbmdzXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUFjY291bnRzZXR0aW5nKGJvZHk6IFguVXBkYXRlQWNjb3VudHNldHRpbmdCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRzZXR0aW5nUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQWNjb3VudHNldHRpbmdSZXNwb25zZT4oJy9hY2NvdW50L3NldHRpbmdzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBY2NvdW50cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hY2NvdW50cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQWNjb3VudHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQWN0aXZhdGUgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEFjdGl2YXRlIEFjY291bnQgYnkgZGVjb2RpbmcgdGhlIGBjb2RlYCB3aGljaCBjb250YWlucyB0aGUgY29uZmlybWF0aW9uIG9mZiB0aGUgaW50ZW50IGFuZCB3YXMgc2lnbmVkIGJ5IHRoZSB1c2VyIGl0c2VsZi5cbiAgICAgKi9cbiAgICBwdWJsaWMgYWN0aXZhdGVBY2NvdW50KGJvZHk6IFguQWN0aXZhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5BY3RpdmF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQWN0aXZhdGVBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY3RpdmF0ZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgTWVudG9ycycgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZSBvbmUgdG8gUmVhZCBhbGwgYXZhaWxhYmxlIE1lbnRvciBhY2NvdW50c1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEFjY291bnRzKHBhcmFtczogWC5CdWxrUmVhZEFjY291bnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5W10+KCcvYXV0aC9hY2NvdW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRBY2NvdW50czIocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5W10+KCcvYXV0aC9hY2NvdW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoYW5nZSBQYXNzd29yZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGNoYW5nZSBvbmUncyBwYXNzd29yZCBmb3IgYW4gYXV0aGVudGljYXRlZCB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyBjaGFuZ2VQYXNzd29yZChib2R5OiBYLkNoYW5nZVBhc3N3b3JkQm9keSk6IE9ic2VydmFibGU8WC5DaGFuZ2VQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DaGFuZ2VQYXNzd29yZFJlc3BvbnNlPignL2F1dGgvY2hhbmdlX3Bhc3N3b3JkLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEFjY291bnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGVzIFVzZXIgYW5kIEFjY291bnQgaWYgcHJvdmlkZWQgZGF0YSBhcmUgdmFsaWQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFjY291bnQoYm9keTogWC5DcmVhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUFjY291bnRSZXNwb25zZT4oJy9hdXRoL2FjY291bnRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgTXkgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgbXkgQWNjb3VudCBkYXRhLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkQWNjb3VudCgpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPignL2F1dGgvYWNjb3VudHMvbWUvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkQWNjb3VudDIoKTogT2JzZXJ2YWJsZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY2NvdW50cy9tZS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXNldCBQYXNzd29yZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIHJlc2V0IGhlciBwYXNzd29yZCBpbiBjYXNlIHRoZSBvbGQgb25lIGNhbm5vdCBiZSByZWNhbGxlZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVzZXRQYXNzd29yZChib2R5OiBYLlJlc2V0UGFzc3dvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlJlc2V0UGFzc3dvcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguUmVzZXRQYXNzd29yZFJlc3BvbnNlPignL2F1dGgvcmVzZXRfcGFzc3dvcmQvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2VuZCBBY2NvdW50IEFjdGl2YXRpb24gRW1haWxcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBTZW5kIGFuIEVtYWlsIGNvbnRhaW5pbmcgdGhlIGNvbmZpcm1hdGlvbiBsaW5rIHdoaWNoIHdoZW4gY2xpY2tlZCBraWNrcyBvZiB0aGUgQWNjb3VudCBBY3RpdmF0aW9uLiBFdmVuIHRob3VnaCB0aGUgYWN0aXZhdGlvbiBlbWFpbCBpcyBzZW5kIGF1dG9tYXRpY2FsbHkgZHVyaW5nIHRoZSBTaWduIFVwIHBoYXNlIG9uZSBzaG91bGQgaGF2ZSBhIHdheSB0byBzZW5kIGl0IGFnYWluIGluIGNhc2UgaXQgd2FzIG5vdCBkZWxpdmVyZWQuXG4gICAgICovXG4gICAgcHVibGljIHNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsKGJvZHk6IFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxCb2R5KTogT2JzZXJ2YWJsZTxYLlNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsUmVzcG9uc2U+KCcvYXV0aC9zZW5kX2FjdGl2YXRpb25fZW1haWwvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2VuZCBSZXNldCBQYXNzd29yZCBFbWFpbFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNlbmQgYW4gRW1haWwgY29udGFpbmluZyB0aGUgY29uZmlybWF0aW9uIGxpbmsgd2hpY2ggd2hlbiBjbGlja2VkIGtpY2tzIG9mIHRoZSByZWFsIFJlc2V0IFBhc3N3b3JkIG9wZXJhdGlvbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgc2VuZFJlc2V0UGFzc3dvcmRFbWFpbChib2R5OiBYLlNlbmRSZXNldFBhc3N3b3JkRW1haWxCb2R5KTogT2JzZXJ2YWJsZTxYLlNlbmRSZXNldFBhc3N3b3JkRW1haWxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbFJlc3BvbnNlPignL2F1dGgvc2VuZF9yZXNldF9wYXNzd29yZF9lbWFpbC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgTXkgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSBteSBBY2NvdW50IGRhdGEuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUFjY291bnQoYm9keTogWC5VcGRhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQWNjb3VudFJlc3BvbnNlPignL2F1dGgvYWNjb3VudHMvbWUvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEFjY291bnRzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvYWN0aXZhdGVfYWNjb3VudC5weS8jbGluZXMtMTAzXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBBY3RpdmF0ZUFjY291bnRCb2R5IHtcbiAgICBjb2RlOiBzdHJpbmc7XG4gICAgZW1haWw6IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQWN0aXZhdGVBY2NvdW50UmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9hY2NvdW50LnB5LyNsaW5lcy0xNzhcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkQWNjb3VudHNRdWVyeSB7XG4gICAgdXNlcl9pZHM6IG51bWJlcltdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0yM1xuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUF0eXBlIHtcbiAgICBBRE1JTiA9ICdBRE1JTicsXG4gICAgRlJFRSA9ICdGUkVFJyxcbiAgICBMRUFSTkVSID0gJ0xFQVJORVInLFxuICAgIE1FTlRPUiA9ICdNRU5UT1InLFxuICAgIFBBUlRORVIgPSAnUEFSVE5FUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5IHtcbiAgICBhdHlwZT86IEJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUF0eXBlO1xuICAgIGF2YXRhcl91cmk/OiBzdHJpbmc7XG4gICAgc2hvd19pbl9yYW5raW5nPzogYm9vbGVhbjtcbiAgICB1c2VyX2lkPzogYW55O1xuICAgIHVzZXJuYW1lPzogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZSB7XG4gICAgYWNjb3VudHM6IEJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2NoYW5nZV9wYXNzd29yZC5weS8jbGluZXMtMjRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENoYW5nZVBhc3N3b3JkQm9keSB7XG4gICAgcGFzc3dvcmQ6IHN0cmluZztcbiAgICBwYXNzd29yZF9hZ2Fpbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDaGFuZ2VQYXNzd29yZFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvYWNjb3VudC5weS8jbGluZXMtMTE0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVBY2NvdW50Qm9keSB7XG4gICAgZW1haWw6IHN0cmluZztcbiAgICBwYXNzd29yZDogc3RyaW5nO1xuICAgIHBhc3N3b3JkX2FnYWluOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUFjY291bnRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy04XG4gKi9cblxuZXhwb3J0IGVudW0gUmVhZEFjY291bnRSZXNwb25zZUF0eXBlIHtcbiAgICBBRE1JTiA9ICdBRE1JTicsXG4gICAgRlJFRSA9ICdGUkVFJyxcbiAgICBMRUFSTkVSID0gJ0xFQVJORVInLFxuICAgIE1FTlRPUiA9ICdNRU5UT1InLFxuICAgIFBBUlRORVIgPSAnUEFSVE5FUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVhZEFjY291bnRSZXNwb25zZSB7XG4gICAgYXR5cGU/OiBSZWFkQWNjb3VudFJlc3BvbnNlQXR5cGU7XG4gICAgYXZhdGFyX3VyaT86IHN0cmluZztcbiAgICBzaG93X2luX3Jhbmtpbmc/OiBib29sZWFuO1xuICAgIHVzZXJfaWQ/OiBhbnk7XG4gICAgdXNlcm5hbWU/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvcmVzZXRfcGFzc3dvcmQucHkvI2xpbmVzLTk0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBSZXNldFBhc3N3b3JkQm9keSB7XG4gICAgY29kZTogc3RyaW5nO1xuICAgIGVtYWlsOiBzdHJpbmc7XG4gICAgcGFzc3dvcmQ6IHN0cmluZztcbiAgICBwYXNzd29yZF9hZ2Fpbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0zMFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVzZXRQYXNzd29yZFJlc3BvbnNlIHtcbiAgICB0b2tlbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2FjdGl2YXRlX2FjY291bnQucHkvI2xpbmVzLTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBTZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbEJvZHkge1xuICAgIGVtYWlsOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9yZXNldF9wYXNzd29yZC5weS8jbGluZXMtMzFcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFNlbmRSZXNldFBhc3N3b3JkRW1haWxCb2R5IHtcbiAgICBlbWFpbDogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBTZW5kUmVzZXRQYXNzd29yZEVtYWlsUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9hY2NvdW50LnB5LyNsaW5lcy01OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgVXBkYXRlQWNjb3VudEJvZHkge1xuICAgIGF2YXRhcl91cmk/OiBzdHJpbmc7XG4gICAgc2hvd19pbl9yYW5raW5nPzogYm9vbGVhbjtcbiAgICB1c2VybmFtZT86IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC9zZXJpYWxpemVycy5weS8jbGluZXMtOFxuICovXG5cbmV4cG9ydCBlbnVtIFVwZGF0ZUFjY291bnRSZXNwb25zZUF0eXBlIHtcbiAgICBBRE1JTiA9ICdBRE1JTicsXG4gICAgRlJFRSA9ICdGUkVFJyxcbiAgICBMRUFSTkVSID0gJ0xFQVJORVInLFxuICAgIE1FTlRPUiA9ICdNRU5UT1InLFxuICAgIFBBUlRORVIgPSAnUEFSVE5FUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgVXBkYXRlQWNjb3VudFJlc3BvbnNlIHtcbiAgICBhdHlwZT86IFVwZGF0ZUFjY291bnRSZXNwb25zZUF0eXBlO1xuICAgIGF2YXRhcl91cmk/OiBzdHJpbmc7XG4gICAgc2hvd19pbl9yYW5raW5nPzogYm9vbGVhbjtcbiAgICB1c2VyX2lkPzogYW55O1xuICAgIHVzZXJuYW1lPzogc3RyaW5nO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQXR0ZW1wdCBTdGF0cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hdHRlbXB0X3N0YXRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBdHRlbXB0U3RhdHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBBdHRlbXB0IFN0YXRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBBdHRlbXB0IFN0YXRzIGJ5IGZpbHRlcmluZyBleGlzdGluZyBvbmVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEF0dGVtcHRzdGF0cyhwYXJhbXM6IFguQnVsa1JlYWRBdHRlbXB0c3RhdHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRfc3RhdHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkQXR0ZW1wdHN0YXRzMihwYXJhbXM6IFguQnVsa1JlYWRBdHRlbXB0c3RhdHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPignL3JlY2FsbC9hdHRlbXB0X3N0YXRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEF0dGVtcHQgU3RhdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZSBBdHRlbXB0IFN0YXQgd2hpY2ggc3RvcmVzIGluZm9ybWF0aW9uIGFib3V0IGJhc2lzIHN0YXRpc3RpY3Mgb2YgYSBwYXJ0aWN1bGFyIHJlY2FsbCBhdHRlbXB0LlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBdHRlbXB0c3RhdChib2R5OiBYLkNyZWF0ZUF0dGVtcHRzdGF0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0c3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBdHRlbXB0c3RhdFJlc3BvbnNlPignL3JlY2FsbC9hdHRlbXB0X3N0YXRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEV4dGVybmFsIEF0dGVtcHQgU3RhdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZSBFeHRlcm5hbCBBdHRlbXB0IFN0YXQgbWVhbmluZyBvbmUgd2hpY2ggd2FzIHJlbmRlcmVkIGVsc2V3aGVyZSBpbiBhbnkgb2YgdGhlIG11bHRpcGxlIENvU3BoZXJlIGFwcHMuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXQoYm9keTogWC5DcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdF9zdGF0cy9leHRlcm5hbC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQXR0ZW1wdHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vYXR0ZW1wdHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF0dGVtcHRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgQXR0ZW1wdHMgQnkgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgQXR0ZW1wdHMgZm9yIGEgc3BlY2lmaWMgQ2FyZCBnaXZlbiBieSBpdHMgSWQuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+KGAvcmVjYWxsL2F0dGVtcHRzL2J5X2NhcmQvJHtjYXJkSWR9YCwgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEF0dGVtcHRzQnlDYXJkczIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+KGAvcmVjYWxsL2F0dGVtcHRzL2J5X2NhcmQvJHtjYXJkSWR9YCwgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEF0dGVtcHRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgQXR0ZW1wdCB3aGljaCBpcyBhIHJlZmxlY3Rpb24gb2Ygc29tZW9uZSdzIGtub3dsZWRnZSByZWdhcmRpbmcgYSBnaXZlbiBDYXJkLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBdHRlbXB0KGJvZHk6IFguQ3JlYXRlQXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBdHRlbXB0UmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIEF0dGVtcHRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgZXhpc3RpbmcgQXR0ZW1wdCB3aXRoIG5ldyBjZWxscyBhbmQgLyBvciBzdHlsZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQXR0ZW1wdChhdHRlbXB0SWQ6IGFueSwgYm9keTogWC5VcGRhdGVBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQXR0ZW1wdFJlc3BvbnNlPihgL3JlY2FsbC9hdHRlbXB0cy8ke2F0dGVtcHRJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQXV0aCBUb2tlbnMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vYXV0aF90b2tlbnMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhUb2tlbnNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQXV0aG9yaXplIGEgZ2l2ZW4gdG9rZW5cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDYW4gYmUgY2FsbGVkIGJ5IHRoZSBBUEkgR2F0ZXdheSBpbiBvcmRlciB0byBhdXRob3JpemUgZXZlcnkgcmVxdWVzdCB1c2luZyBwcm92aWRlZCB0b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgYXV0aG9yaXplQXV0aFRva2VuKCk6IE9ic2VydmFibGU8WC5BdXRob3JpemVBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQXV0aG9yaXplQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9hdXRob3JpemUvJywge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNpZ24gSW5cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBWYWxpZGF0ZXMgZGF0YSBwcm92aWRlZCBvbiB0aGUgaW5wdXQgYW5kIGlmIHN1Y2Nlc3NmdWwgcmV0dXJucyBhdXRoIHRva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBGYWNlYm9vayBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2ZhY2Vib29rLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBNb2JpbGUgRmFjZWJvb2sgQXV0aCBUb2tlblxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9mYWNlYm9vay9tb2JpbGUvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEdvb2dsZSBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9nb29nbGUvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1vYmlsZSBHb29nbGUgQXV0aCBUb2tlblxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvZ29vZ2xlL21vYmlsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWZyZXNoIEpXVCB0b2tlblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNob3VsZCBiZSB1c2VkIHdoZW5ldmVyIHRva2VuIGlzIGNsb3NlIHRvIGV4cGlyeSBvciBpZiBvbmUgaXMgcmVxdWVzdGVkIHRvIHJlZnJlc2ggdGhlIHRva2VuIGJlY2F1c2UgZm9yIGV4YW1wbGUgYWNjb3VudCB0eXBlIHdhcyBjaGFuZ2VkIGFuZCBuZXcgdG9rZW4gc2hvdWxkIGJlIHJlcXVlc3RlZCB0byByZWZsZWN0IHRoYXQgY2hhbmdlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZUF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvJywge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBCcmlja3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vYnJpY2tzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBCcmlja3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQnVsayBSZWFkIEJyaWNrcyBHYW1lIEF0dGVtcHRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkR2FtZWF0dGVtcHRzKGdhbWVJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRHYW1lYXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEdhbWVhdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+KGAvZ2FtZXMvJHtnYW1lSWR9L2F0dGVtcHRzL2AsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRHYW1lYXR0ZW1wdHMyKGdhbWVJZDogYW55KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkR2FtZWF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRHYW1lYXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPihgL2dhbWVzLyR7Z2FtZUlkfS9hdHRlbXB0cy9gLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgR2FtZVxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEdhbWVzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2FtZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEdhbWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9nYW1lcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkR2FtZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEdhbWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRHYW1lc1Jlc3BvbnNlRW50aXR5W10+KCcvZ2FtZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEdhbWVcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlR2FtZShib2R5OiBYLkNyZWF0ZUdhbWVCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdhbWVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlR2FtZVJlc3BvbnNlPignL2dhbWVzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEJyaWNrcyBHYW1lIEF0dGVtcHRcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlR2FtZWF0dGVtcHQoZ2FtZUlkOiBhbnksIGJvZHk6IFguQ3JlYXRlR2FtZWF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdhbWVhdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUdhbWVhdHRlbXB0UmVzcG9uc2U+KGAvZ2FtZXMvJHtnYW1lSWR9L2F0dGVtcHRzL2AsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVsZXRlIEdhbWVcbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlR2FtZShnYW1lSWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVHYW1lUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlR2FtZVJlc3BvbnNlPihgL2dhbWVzLyR7Z2FtZUlkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBHYW1lXG4gICAgICovXG4gICAgcHVibGljIHJlYWRHYW1lKGdhbWVJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEdhbWVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEdhbWVSZXNwb25zZT4oYC9nYW1lcy8ke2dhbWVJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRHYW1lMihnYW1lSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkR2FtZVJlc3BvbnNlPihgL2dhbWVzLyR7Z2FtZUlkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBHYW1lXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUdhbWUoZ2FtZUlkOiBhbnksIGJvZHk6IFguVXBkYXRlR2FtZUJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZUdhbWVSZXNwb25zZT4oYC9nYW1lcy8ke2dhbWVJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQnJpY2tzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hcHAtYnJpY2tzLWJlL3NyYy85ZGZlODYxNjhlY2MxYmVhYzBjZTIyYTZiYTIwMDE2M2YzMTdmZGJhL2Nvc3BoZXJlX2FwcF9icmlja3NfYmUvZ2FtZS9zZXJpYWxpemVycy5weS8jbGluZXMtNzFcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkR2FtZWF0dGVtcHRzUmVzcG9uc2VFbnRpdHkge1xuICAgIGF0dGVtcHQ/OiBPYmplY3Q7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBnYW1lX2lkPzogYW55O1xuICAgIGlkPzogbnVtYmVyO1xuICAgIHN0YXJ0X3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIHVzZXJfaWQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEdhbWVhdHRlbXB0c1Jlc3BvbnNlIHtcbiAgICBhdHRlbXB0czogQnVsa1JlYWRHYW1lYXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXBwLWJyaWNrcy1iZS9zcmMvOWRmZTg2MTY4ZWNjMWJlYWMwY2UyMmE2YmEyMDAxNjNmMzE3ZmRiYS9jb3NwaGVyZV9hcHBfYnJpY2tzX2JlL2dhbWUvc2VyaWFsaXplcnMucHkvI2xpbmVzLTI1XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEdhbWVzUmVzcG9uc2VFbnRpdHkge1xuICAgIGJyaWNrczogT2JqZWN0O1xuICAgIGNhdGVnb3JpZXM6IE9iamVjdDtcbiAgICBjaGFsbGVuZ2U/OiBzdHJpbmc7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgdGVybXM6IE9iamVjdDtcbiAgICB0aXRsZTogc3RyaW5nO1xuICAgIHVzZXJfaWQ6IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEdhbWVzUmVzcG9uc2Uge1xuICAgIGdhbWVzOiBCdWxrUmVhZEdhbWVzUmVzcG9uc2VFbnRpdHlbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvY29zcGhlcmVfYXBwX2JyaWNrc19iZS9nYW1lL3BhcnNlcnMucHkvI2xpbmVzLTU0XG4gKi9cblxuZXhwb3J0IGVudW0gQ3JlYXRlR2FtZUJvZHlBdWRpb0xhbmd1YWdlIHtcbiAgICBjeSA9ICdjeScsXG4gICAgZGEgPSAnZGEnLFxuICAgIGRlID0gJ2RlJyxcbiAgICBlbiA9ICdlbicsXG4gICAgZXMgPSAnZXMnLFxuICAgIGZyID0gJ2ZyJyxcbiAgICBpcyA9ICdpcycsXG4gICAgaXQgPSAnaXQnLFxuICAgIGphID0gJ2phJyxcbiAgICBrbyA9ICdrbycsXG4gICAgbmIgPSAnbmInLFxuICAgIG5sID0gJ25sJyxcbiAgICBwbCA9ICdwbCcsXG4gICAgcHQgPSAncHQnLFxuICAgIHJvID0gJ3JvJyxcbiAgICBydSA9ICdydScsXG4gICAgc3YgPSAnc3YnLFxuICAgIHRyID0gJ3RyJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlR2FtZUJvZHlMYW5ndWFnZSB7XG4gICAgYWYgPSAnYWYnLFxuICAgIGFtID0gJ2FtJyxcbiAgICBhbiA9ICdhbicsXG4gICAgYXIgPSAnYXInLFxuICAgIGFzID0gJ2FzJyxcbiAgICBheiA9ICdheicsXG4gICAgYmUgPSAnYmUnLFxuICAgIGJnID0gJ2JnJyxcbiAgICBibiA9ICdibicsXG4gICAgYnIgPSAnYnInLFxuICAgIGJzID0gJ2JzJyxcbiAgICBjYSA9ICdjYScsXG4gICAgY3MgPSAnY3MnLFxuICAgIGN5ID0gJ2N5JyxcbiAgICBkYSA9ICdkYScsXG4gICAgZGUgPSAnZGUnLFxuICAgIGR6ID0gJ2R6JyxcbiAgICBlbCA9ICdlbCcsXG4gICAgZW4gPSAnZW4nLFxuICAgIGVvID0gJ2VvJyxcbiAgICBlcyA9ICdlcycsXG4gICAgZXQgPSAnZXQnLFxuICAgIGV1ID0gJ2V1JyxcbiAgICBmYSA9ICdmYScsXG4gICAgZmkgPSAnZmknLFxuICAgIGZvID0gJ2ZvJyxcbiAgICBmciA9ICdmcicsXG4gICAgZ2EgPSAnZ2EnLFxuICAgIGdsID0gJ2dsJyxcbiAgICBndSA9ICdndScsXG4gICAgaGUgPSAnaGUnLFxuICAgIGhpID0gJ2hpJyxcbiAgICBociA9ICdocicsXG4gICAgaHQgPSAnaHQnLFxuICAgIGh1ID0gJ2h1JyxcbiAgICBoeSA9ICdoeScsXG4gICAgaWQgPSAnaWQnLFxuICAgIGlzID0gJ2lzJyxcbiAgICBpdCA9ICdpdCcsXG4gICAgamEgPSAnamEnLFxuICAgIGp2ID0gJ2p2JyxcbiAgICBrYSA9ICdrYScsXG4gICAga2sgPSAna2snLFxuICAgIGttID0gJ2ttJyxcbiAgICBrbiA9ICdrbicsXG4gICAga28gPSAna28nLFxuICAgIGt1ID0gJ2t1JyxcbiAgICBreSA9ICdreScsXG4gICAgbGEgPSAnbGEnLFxuICAgIGxiID0gJ2xiJyxcbiAgICBsbyA9ICdsbycsXG4gICAgbHQgPSAnbHQnLFxuICAgIGx2ID0gJ2x2JyxcbiAgICBtZyA9ICdtZycsXG4gICAgbWsgPSAnbWsnLFxuICAgIG1sID0gJ21sJyxcbiAgICBtbiA9ICdtbicsXG4gICAgbXIgPSAnbXInLFxuICAgIG1zID0gJ21zJyxcbiAgICBtdCA9ICdtdCcsXG4gICAgbmIgPSAnbmInLFxuICAgIG5lID0gJ25lJyxcbiAgICBubCA9ICdubCcsXG4gICAgbm4gPSAnbm4nLFxuICAgIG5vID0gJ25vJyxcbiAgICBvYyA9ICdvYycsXG4gICAgb3IgPSAnb3InLFxuICAgIHBhID0gJ3BhJyxcbiAgICBwbCA9ICdwbCcsXG4gICAgcHMgPSAncHMnLFxuICAgIHB0ID0gJ3B0JyxcbiAgICBxdSA9ICdxdScsXG4gICAgcm8gPSAncm8nLFxuICAgIHJ1ID0gJ3J1JyxcbiAgICBydyA9ICdydycsXG4gICAgc2UgPSAnc2UnLFxuICAgIHNpID0gJ3NpJyxcbiAgICBzayA9ICdzaycsXG4gICAgc2wgPSAnc2wnLFxuICAgIHNxID0gJ3NxJyxcbiAgICBzciA9ICdzcicsXG4gICAgc3YgPSAnc3YnLFxuICAgIHN3ID0gJ3N3JyxcbiAgICB0YSA9ICd0YScsXG4gICAgdGUgPSAndGUnLFxuICAgIHRoID0gJ3RoJyxcbiAgICB0bCA9ICd0bCcsXG4gICAgdHIgPSAndHInLFxuICAgIHVnID0gJ3VnJyxcbiAgICB1ayA9ICd1aycsXG4gICAgdXIgPSAndXInLFxuICAgIHZpID0gJ3ZpJyxcbiAgICB2byA9ICd2bycsXG4gICAgd2EgPSAnd2EnLFxuICAgIHhoID0gJ3hoJyxcbiAgICB6aCA9ICd6aCcsXG4gICAgenUgPSAnenUnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUdhbWVCb2R5IHtcbiAgICBicmlja3M6IHtcbiAgICAgICAgYmFja2dyb3VuZD86IHtcbiAgICAgICAgICAgIGF1ZGlvX2xhbmd1YWdlPzogQ3JlYXRlR2FtZUJvZHlBdWRpb0xhbmd1YWdlO1xuICAgICAgICAgICAgYXVkaW9fdGV4dD86IHN0cmluZztcbiAgICAgICAgICAgIGF1ZGlvX3VyaT86IHN0cmluZztcbiAgICAgICAgfTtcbiAgICAgICAgY2F0ZWdvcnlfY2lkOiBudW1iZXI7XG4gICAgICAgIGNhdGVnb3J5X2lkPzogbnVtYmVyO1xuICAgICAgICBjaWQ6IG51bWJlcjtcbiAgICAgICAgZm9yZWdyb3VuZD86IHtcbiAgICAgICAgICAgIGltYWdlX3VyaT86IHN0cmluZztcbiAgICAgICAgICAgIGxhbmd1YWdlPzogQ3JlYXRlR2FtZUJvZHlMYW5ndWFnZTtcbiAgICAgICAgICAgIHRleHQ/OiBzdHJpbmc7XG4gICAgICAgIH07XG4gICAgICAgIGlkPzogbnVtYmVyO1xuICAgICAgICByZWFzb24/OiBzdHJpbmc7XG4gICAgfVtdO1xuICAgIGNhdGVnb3JpZXM6IHtcbiAgICAgICAgY2lkOiBudW1iZXI7XG4gICAgICAgIGlkPzogbnVtYmVyO1xuICAgICAgICB0ZXh0OiBzdHJpbmc7XG4gICAgfVtdO1xuICAgIGNoYWxsZW5nZTogc3RyaW5nO1xuICAgIHRpdGxlOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hcHAtYnJpY2tzLWJlL3NyYy85ZGZlODYxNjhlY2MxYmVhYzBjZTIyYTZiYTIwMDE2M2YzMTdmZGJhL2Nvc3BoZXJlX2FwcF9icmlja3NfYmUvZ2FtZS9zZXJpYWxpemVycy5weS8jbGluZXMtN1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlR2FtZVJlc3BvbnNlIHtcbiAgICBicmlja3M6IE9iamVjdDtcbiAgICBjYXRlZ29yaWVzOiBPYmplY3Q7XG4gICAgY2hhbGxlbmdlPzogc3RyaW5nO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIHRlcm1zOiBPYmplY3Q7XG4gICAgdGl0bGU6IHN0cmluZztcbiAgICB1c2VyX2lkOiBudW1iZXI7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hcHAtYnJpY2tzLWJlL3NyYy85ZGZlODYxNjhlY2MxYmVhYzBjZTIyYTZiYTIwMDE2M2YzMTdmZGJhL2Nvc3BoZXJlX2FwcF9icmlja3NfYmUvZ2FtZS9wYXJzZXJzLnB5LyNsaW5lcy03MlxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlR2FtZWF0dGVtcHRCb2R5IHtcbiAgICBhdHRlbXB0OiB7XG4gICAgICAgIGJyaWNrX2lkOiBudW1iZXI7XG4gICAgICAgIGNhdGVnb3J5X2lkOiBudW1iZXI7XG4gICAgfVtdO1xuICAgIHN0YXJ0X2RhdGV0aW1lOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hcHAtYnJpY2tzLWJlL3NyYy85ZGZlODYxNjhlY2MxYmVhYzBjZTIyYTZiYTIwMDE2M2YzMTdmZGJhL2Nvc3BoZXJlX2FwcF9icmlja3NfYmUvZ2FtZS9zZXJpYWxpemVycy5weS8jbGluZXMtNDFcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUdhbWVhdHRlbXB0UmVzcG9uc2Uge1xuICAgIGF0dGVtcHQ/OiBPYmplY3Q7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBnYW1lX2lkPzogYW55O1xuICAgIGlkPzogbnVtYmVyO1xuICAgIHN0YXJ0X3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIHVzZXJfaWQ6IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIERlbGV0ZUdhbWVSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXBwLWJyaWNrcy1iZS9zcmMvOWRmZTg2MTY4ZWNjMWJlYWMwY2UyMmE2YmEyMDAxNjNmMzE3ZmRiYS9jb3NwaGVyZV9hcHBfYnJpY2tzX2JlL2dhbWUvc2VyaWFsaXplcnMucHkvI2xpbmVzLTdcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFJlYWRHYW1lUmVzcG9uc2Uge1xuICAgIGJyaWNrczogT2JqZWN0O1xuICAgIGNhdGVnb3JpZXM6IE9iamVjdDtcbiAgICBjaGFsbGVuZ2U/OiBzdHJpbmc7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgdGVybXM6IE9iamVjdDtcbiAgICB0aXRsZTogc3RyaW5nO1xuICAgIHVzZXJfaWQ6IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWFwcC1icmlja3MtYmUvc3JjLzlkZmU4NjE2OGVjYzFiZWFjMGNlMjJhNmJhMjAwMTYzZjMxN2ZkYmEvY29zcGhlcmVfYXBwX2JyaWNrc19iZS9nYW1lL3BhcnNlcnMucHkvI2xpbmVzLTU0XG4gKi9cblxuZXhwb3J0IGVudW0gVXBkYXRlR2FtZUJvZHlBdWRpb0xhbmd1YWdlIHtcbiAgICBjeSA9ICdjeScsXG4gICAgZGEgPSAnZGEnLFxuICAgIGRlID0gJ2RlJyxcbiAgICBlbiA9ICdlbicsXG4gICAgZXMgPSAnZXMnLFxuICAgIGZyID0gJ2ZyJyxcbiAgICBpcyA9ICdpcycsXG4gICAgaXQgPSAnaXQnLFxuICAgIGphID0gJ2phJyxcbiAgICBrbyA9ICdrbycsXG4gICAgbmIgPSAnbmInLFxuICAgIG5sID0gJ25sJyxcbiAgICBwbCA9ICdwbCcsXG4gICAgcHQgPSAncHQnLFxuICAgIHJvID0gJ3JvJyxcbiAgICBydSA9ICdydScsXG4gICAgc3YgPSAnc3YnLFxuICAgIHRyID0gJ3RyJyxcbn1cblxuZXhwb3J0IGVudW0gVXBkYXRlR2FtZUJvZHlMYW5ndWFnZSB7XG4gICAgYWYgPSAnYWYnLFxuICAgIGFtID0gJ2FtJyxcbiAgICBhbiA9ICdhbicsXG4gICAgYXIgPSAnYXInLFxuICAgIGFzID0gJ2FzJyxcbiAgICBheiA9ICdheicsXG4gICAgYmUgPSAnYmUnLFxuICAgIGJnID0gJ2JnJyxcbiAgICBibiA9ICdibicsXG4gICAgYnIgPSAnYnInLFxuICAgIGJzID0gJ2JzJyxcbiAgICBjYSA9ICdjYScsXG4gICAgY3MgPSAnY3MnLFxuICAgIGN5ID0gJ2N5JyxcbiAgICBkYSA9ICdkYScsXG4gICAgZGUgPSAnZGUnLFxuICAgIGR6ID0gJ2R6JyxcbiAgICBlbCA9ICdlbCcsXG4gICAgZW4gPSAnZW4nLFxuICAgIGVvID0gJ2VvJyxcbiAgICBlcyA9ICdlcycsXG4gICAgZXQgPSAnZXQnLFxuICAgIGV1ID0gJ2V1JyxcbiAgICBmYSA9ICdmYScsXG4gICAgZmkgPSAnZmknLFxuICAgIGZvID0gJ2ZvJyxcbiAgICBmciA9ICdmcicsXG4gICAgZ2EgPSAnZ2EnLFxuICAgIGdsID0gJ2dsJyxcbiAgICBndSA9ICdndScsXG4gICAgaGUgPSAnaGUnLFxuICAgIGhpID0gJ2hpJyxcbiAgICBociA9ICdocicsXG4gICAgaHQgPSAnaHQnLFxuICAgIGh1ID0gJ2h1JyxcbiAgICBoeSA9ICdoeScsXG4gICAgaWQgPSAnaWQnLFxuICAgIGlzID0gJ2lzJyxcbiAgICBpdCA9ICdpdCcsXG4gICAgamEgPSAnamEnLFxuICAgIGp2ID0gJ2p2JyxcbiAgICBrYSA9ICdrYScsXG4gICAga2sgPSAna2snLFxuICAgIGttID0gJ2ttJyxcbiAgICBrbiA9ICdrbicsXG4gICAga28gPSAna28nLFxuICAgIGt1ID0gJ2t1JyxcbiAgICBreSA9ICdreScsXG4gICAgbGEgPSAnbGEnLFxuICAgIGxiID0gJ2xiJyxcbiAgICBsbyA9ICdsbycsXG4gICAgbHQgPSAnbHQnLFxuICAgIGx2ID0gJ2x2JyxcbiAgICBtZyA9ICdtZycsXG4gICAgbWsgPSAnbWsnLFxuICAgIG1sID0gJ21sJyxcbiAgICBtbiA9ICdtbicsXG4gICAgbXIgPSAnbXInLFxuICAgIG1zID0gJ21zJyxcbiAgICBtdCA9ICdtdCcsXG4gICAgbmIgPSAnbmInLFxuICAgIG5lID0gJ25lJyxcbiAgICBubCA9ICdubCcsXG4gICAgbm4gPSAnbm4nLFxuICAgIG5vID0gJ25vJyxcbiAgICBvYyA9ICdvYycsXG4gICAgb3IgPSAnb3InLFxuICAgIHBhID0gJ3BhJyxcbiAgICBwbCA9ICdwbCcsXG4gICAgcHMgPSAncHMnLFxuICAgIHB0ID0gJ3B0JyxcbiAgICBxdSA9ICdxdScsXG4gICAgcm8gPSAncm8nLFxuICAgIHJ1ID0gJ3J1JyxcbiAgICBydyA9ICdydycsXG4gICAgc2UgPSAnc2UnLFxuICAgIHNpID0gJ3NpJyxcbiAgICBzayA9ICdzaycsXG4gICAgc2wgPSAnc2wnLFxuICAgIHNxID0gJ3NxJyxcbiAgICBzciA9ICdzcicsXG4gICAgc3YgPSAnc3YnLFxuICAgIHN3ID0gJ3N3JyxcbiAgICB0YSA9ICd0YScsXG4gICAgdGUgPSAndGUnLFxuICAgIHRoID0gJ3RoJyxcbiAgICB0bCA9ICd0bCcsXG4gICAgdHIgPSAndHInLFxuICAgIHVnID0gJ3VnJyxcbiAgICB1ayA9ICd1aycsXG4gICAgdXIgPSAndXInLFxuICAgIHZpID0gJ3ZpJyxcbiAgICB2byA9ICd2bycsXG4gICAgd2EgPSAnd2EnLFxuICAgIHhoID0gJ3hoJyxcbiAgICB6aCA9ICd6aCcsXG4gICAgenUgPSAnenUnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFVwZGF0ZUdhbWVCb2R5IHtcbiAgICBicmlja3M6IHtcbiAgICAgICAgYmFja2dyb3VuZD86IHtcbiAgICAgICAgICAgIGF1ZGlvX2xhbmd1YWdlPzogVXBkYXRlR2FtZUJvZHlBdWRpb0xhbmd1YWdlO1xuICAgICAgICAgICAgYXVkaW9fdGV4dD86IHN0cmluZztcbiAgICAgICAgICAgIGF1ZGlvX3VyaT86IHN0cmluZztcbiAgICAgICAgfTtcbiAgICAgICAgY2F0ZWdvcnlfY2lkOiBudW1iZXI7XG4gICAgICAgIGNhdGVnb3J5X2lkPzogbnVtYmVyO1xuICAgICAgICBjaWQ6IG51bWJlcjtcbiAgICAgICAgZm9yZWdyb3VuZD86IHtcbiAgICAgICAgICAgIGltYWdlX3VyaT86IHN0cmluZztcbiAgICAgICAgICAgIGxhbmd1YWdlPzogVXBkYXRlR2FtZUJvZHlMYW5ndWFnZTtcbiAgICAgICAgICAgIHRleHQ/OiBzdHJpbmc7XG4gICAgICAgIH07XG4gICAgICAgIGlkPzogbnVtYmVyO1xuICAgICAgICByZWFzb24/OiBzdHJpbmc7XG4gICAgfVtdO1xuICAgIGNhdGVnb3JpZXM6IHtcbiAgICAgICAgY2lkOiBudW1iZXI7XG4gICAgICAgIGlkPzogbnVtYmVyO1xuICAgICAgICB0ZXh0OiBzdHJpbmc7XG4gICAgfVtdO1xuICAgIGNoYWxsZW5nZTogc3RyaW5nO1xuICAgIHRpdGxlOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hcHAtYnJpY2tzLWJlL3NyYy85ZGZlODYxNjhlY2MxYmVhYzBjZTIyYTZiYTIwMDE2M2YzMTdmZGJhL2Nvc3BoZXJlX2FwcF9icmlja3NfYmUvZ2FtZS9zZXJpYWxpemVycy5weS8jbGluZXMtN1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgVXBkYXRlR2FtZVJlc3BvbnNlIHtcbiAgICBicmlja3M6IE9iamVjdDtcbiAgICBjYXRlZ29yaWVzOiBPYmplY3Q7XG4gICAgY2hhbGxlbmdlPzogc3RyaW5nO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIHRlcm1zOiBPYmplY3Q7XG4gICAgdGl0bGU6IHN0cmluZztcbiAgICB1c2VyX2lkOiBudW1iZXI7XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBDYXJkcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9jYXJkcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ2FyZHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZW1vdmUgbGlzdCBvZiBDYXJkcyBzcGVjaWZpZWQgYnkgdGhlaXIgaWRzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrRGVsZXRlQ2FyZHMocGFyYW1zOiBYLkJ1bGtEZWxldGVDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtEZWxldGVDYXJkc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkJ1bGtEZWxldGVDYXJkc1Jlc3BvbnNlPignL2NhcmRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgTXVsdGlwbGUgQ2FyZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IHN1YnNldCBvZiBDYXJkcyBkZXBlbmRpbmcgb24gdmFyaW91cyBmaWx0ZXJpbmcgZmxhZ3MuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQ2FyZHMocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXJkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRDYXJkczIocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+KCcvY2FyZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGluZyBhIHNpbmdsZSBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY3JlYXRlIGEgc2luZ2xlIENhcmQgaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUNhcmQoYm9keTogWC5DcmVhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUNhcmRSZXNwb25zZT4oJy9jYXJkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgQ2FyZCBieSBJZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgQ2FyZCBieSBgaWRgLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkQ2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+KGAvY2FyZHMvJHtjYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkQ2FyZDIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZENhcmRSZXNwb25zZT4oYC9jYXJkcy8ke2NhcmRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGluZyBhIHNpbmdsZSBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY3JlYXRlIGEgc2luZ2xlIENhcmQgaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUNhcmQoY2FyZElkOiBhbnksIGJvZHk6IFguVXBkYXRlQ2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZUNhcmRSZXNwb25zZT4oYC9jYXJkcy8ke2NhcmRJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQ2F0ZWdvcmllcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9jYXRlZ29yaWVzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDYXRlZ29yaWVzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgQ2F0ZWdvcmllc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgQ2F0ZWdvcmllcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRDYXRlZ29yaWVzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5W10+KCcvY2F0ZWdvcmllcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkQ2F0ZWdvcmllczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5W10+KCcvY2F0ZWdvcmllcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIENhdGVnb3JpZXMgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy81ZjIxNWZhYmJhN2ZhMzkyNTE1MWMwOThmYWQwMDUxMTYyNDUyODIxL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL2NhdGVnb3J5L3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0yN1xuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlVGV4dCB7XG4gICAgRk9SR09UVEVOID0gJ0ZPUkdPVFRFTicsXG4gICAgSE9UID0gJ0hPVCcsXG4gICAgTk9UX1JFQ0FMTEVEID0gJ05PVF9SRUNBTExFRCcsXG4gICAgUFJPQkxFTUFUSUMgPSAnUFJPQkxFTUFUSUMnLFxuICAgIFJFQ0VOVExZX0FEREVEID0gJ1JFQ0VOVExZX0FEREVEJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eSB7XG4gICAgY291bnQ6IG51bWJlcjtcbiAgICBpZD86IG51bWJlcjtcbiAgICB0ZXh0OiBCdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZVRleHQ7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2Uge1xuICAgIGNhdGVnb3JpZXM6IEJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5W107XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBDb250YWN0IE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2NvbnRhY3RzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDb250YWN0c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgQW5vbnltb3VzIENvbnRhY3QgQXR0ZW1wdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIHNlbmQgbWVzc2FnZXMgdG8gQ29TcGhlcmUncyBzdXBwb3J0IGV2ZW4gaWYgdGhlIHNlbmRlciBpcyBub3QgYXV0aGVudGljYXRlZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHQoYm9keTogWC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHRSZXNwb25zZT4oJy9jb250YWN0cy9hbm9ueW1vdXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2VuZCBBdXRoZW50aWNhdGVkIENvbnRhY3QgTWVzc2FnZVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNlbmQgdGhlIENvbnRhY3QgTWVzc2FnZSBpbW1lZGlhdGVseSBzaW5jZSBpdCdzIGFscmVhZHkgZm9yIGFuIGV4aXN0aW5nIGFuZCBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIHNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2UoYm9keTogWC5TZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlQm9keSk6IE9ic2VydmFibGU8WC5TZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2VSZXNwb25zZT4oJy9jb250YWN0cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFZlcmlmeSB0aGUgY29udGFjdCBhdHRlbXB0XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVmVyaWZ5IHRoZSBjb3JyZWN0bmVzcyBvZiBwcm92aWRlZCB2ZXJpZmljYXRpb24gY29kZSBhbmQgc2VuZCB0aGUgbWVzc2FnZSB0byB0aGUgQ29TcGhlcmUncyBzdXBwb3J0LiBUaGlzIG1lY2hhbmlzbSBpcyB1c2VkIGZvciBhbm9ueW1vdXMgdXNlcnMgb25seS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHQoYm9keTogWC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguVmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguVmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHRSZXNwb25zZT4oJy9jb250YWN0cy9hbm9ueW1vdXMvdmVyaWZ5LycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRG9uYXRpb25zIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2RvbmF0aW9ucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRG9uYXRpb25zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIENoZWNrIGlmIG9uZSBjYW4gYXR0ZW1wdCBhIHJlcXVlc3QgZGlzcGxheWluZyBkb25hdGlvblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNpbmNlIHdlIGRvbid0IHdhbnQgdG8gb3ZlcmZsb3cgdXNlciB3aXRoIHVubmVjZXNzYXJ5IHJlcXVlc3RzIGZvciBoaW0gZG9uYXRpbmcgd2UgZG8gaXQgaW4gYSBzbWFydGVyIHdheSB1c2luZyBzZXQgb2YgaGV1cmlzdGljcyB0aGF0IHRvZ2V0aGVyIGhlbHAgdXMgdG8gYW5zd2VyIHRoZSBmb2xsb3dpbmcgcXVlc3Rpb246IFwiSXMgaXQgdGhlIGJlc3QgbW9tZW50IHRvIGFzayBmb3IgdGhlIGRvbmF0aW9uP1wiLiBDdXJyZW50bHkgd2UgdXNlIHRoZSBmb2xsb3dpbmcgaGV1cmlzdGljczogLSBpcyBhY2NvdW50IG9sZCBlbm91Z2g/IC0gd2hldGhlciB1c2VyIHJlY2VudGx5IGRvbmF0ZWQgLSB3aGV0aGVyIHdlIGF0dGVtcHRlZCByZWNlbnRseSB0byByZXF1ZXN0IGRvbmF0aW9uIGZyb20gdGhlIHVzZXIgLSBpZiB0aGUgdXNlciBpbiBhIGdvb2QgbW9vZCAoYWZ0ZXIgZG9pbmcgc29tZSBzdWNjZXNzZnVsIHJlY2FsbHMpXG4gICAgICovXG4gICAgcHVibGljIGNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb24ocGFyYW1zOiBYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25RdWVyeSk6IERhdGFTdGF0ZTxYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPignL3BheW1lbnRzL2RvbmF0aW9ucy9jYW5fYXR0ZW1wdC8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbjIocGFyYW1zOiBYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25RdWVyeSk6IE9ic2VydmFibGU8WC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZT4oJy9wYXltZW50cy9kb25hdGlvbnMvY2FuX2F0dGVtcHQvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWdpc3RlciBhbm9ueW1vdXMgZG9uYXRpb25cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBPbmUgY2FuIHBlcmZvcm0gYSBkb25hdGlvbiBwYXltZW50IGV2ZW4gaWYgbm90IGJlaW5nIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci4gRXZlbiBpbiB0aGF0IGNhc2Ugd2UgY2Fubm90IGFsbG93IGZ1bGwgYW5vbnltaXR5IGFuZCB3ZSBtdXN0IHJlcXVpcmUgYXQgbGVhc3QgZW1haWwgYWRkcmVzcyB0byBzZW5kIGluZm9ybWF0aW9uIHJlZ2FyZGluZyB0aGUgc3RhdHVzIG9mIHRoZSBwYXltZW50LlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBbm9ueW1vdXNEb25hdGlvbihib2R5OiBYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlPignL3BheW1lbnRzL2RvbmF0aW9ucy9yZWdpc3Rlcl9hbm9ueW1vdXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVnaXN0ZXIgZG9uYXRpb24gZnJvbSBhdXRoZW50aWNhdGVkIHVzZXJcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBPbmUgY2FuIHBlcmZvcm0gYSBkb25hdGlvbiBwYXltZW50IGV2ZW4gYXMgYW4gYXV0aGVudGljYXRlZCB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVEb25hdGlvbihib2R5OiBYLkNyZWF0ZURvbmF0aW9uQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVEb25hdGlvblJlc3BvbnNlPignL3BheW1lbnRzL2RvbmF0aW9ucy9yZWdpc3Rlci8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBkb25hdGlvbiBhdHRlbXB0IGZvciBhdXRoZW50aWNhdGVkIHVzZXJcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFYWNoIERvbmF0aW9uIEF0dGVtcHQgc2hvdWxkIGJlIGZvbGxvd2VkIGJ5IGNyZWF0aW9uIG9mIERvbmF0aW9uIEF0dGVtcHQgbW9kZWwgaW5zdGFuY2UgdG8gcmVmbGVjdCB0aGF0IGZhY3QuIEl0IGFsbG93cyBvbmUgdG8gdHJhY2sgaG93IG1hbnkgdGltZXMgd2UgYXNrZWQgYSBjZXJ0YWluIHVzZXIgYWJvdXQgdGhlIGRvbmF0aW9uIGluIG9yZGVyIG5vdCB0byBvdmVyZmxvdyB0aGF0IHVzZXIgd2l0aCB0aGVtIGFuZCBub3QgdG8gYmUgdG9vIGFnZ3Jlc3NpdmUuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZURvbmF0aW9uYXR0ZW1wdChib2R5OiBYLkNyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlPignL3BheW1lbnRzL2RvbmF0aW9ucy9hdHRlbXB0cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRG9uYXRpb25zIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvZG9uYXRpb24ucHkvI2xpbmVzLTMwXG4gKi9cblxuZXhwb3J0IGVudW0gQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5RXZlbnQge1xuICAgIENMT1NFID0gJ0NMT1NFJyxcbiAgICBSRUNBTEwgPSAnUkVDQUxMJyxcbiAgICBTVEFSVCA9ICdTVEFSVCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5IHtcbiAgICBldmVudDogQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5RXZlbnQ7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvZG9uYXRpb24ucHkvI2xpbmVzLTM0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2Uge1xuICAgIGNhbl9hdHRlbXB0OiBib29sZWFuO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL2RvbmF0aW9uLnB5LyNsaW5lcy0xODRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUFub255bW91c0RvbmF0aW9uQm9keSB7XG4gICAgYW1vdW50OiBudW1iZXI7XG4gICAgZW1haWw6IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9wYXltZW50LnB5LyNsaW5lcy05XG4gKi9cblxuZXhwb3J0IGVudW0gQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2VTdGF0dXMge1xuICAgIENBTkNFTEVEID0gJ0NBTkNFTEVEJyxcbiAgICBDT01QTEVURUQgPSAnQ09NUExFVEVEJyxcbiAgICBORVcgPSAnTkVXJyxcbiAgICBQRU5ESU5HID0gJ1BFTkRJTkcnLFxuICAgIFJFSkVDVEVEID0gJ1JFSkVDVEVEJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlIHtcbiAgICBhbW91bnQ6IHN0cmluZztcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGRpc3BsYXlfYW1vdW50OiBzdHJpbmc7XG4gICAgcHJvZHVjdDoge1xuICAgICAgICBjdXJyZW5jeT86IENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgZGlzcGxheV9wcmljZTogc3RyaW5nO1xuICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0X3R5cGU6IENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2VQcm9kdWN0VHlwZTtcbiAgICB9O1xuICAgIHN0YXR1cz86IENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2VTdGF0dXM7XG4gICAgc3RhdHVzX2xlZGdlcj86IE9iamVjdDtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9kb25hdGlvbi5weS8jbGluZXMtMTg0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVEb25hdGlvbkJvZHkge1xuICAgIGFtb3VudDogbnVtYmVyO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnQucHkvI2xpbmVzLTlcbiAqL1xuXG5leHBvcnQgZW51bSBDcmVhdGVEb25hdGlvblJlc3BvbnNlQ3VycmVuY3kge1xuICAgIFBMTiA9ICdQTE4nLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlRG9uYXRpb25SZXNwb25zZVN0YXR1cyB7XG4gICAgQ0FOQ0VMRUQgPSAnQ0FOQ0VMRUQnLFxuICAgIENPTVBMRVRFRCA9ICdDT01QTEVURUQnLFxuICAgIE5FVyA9ICdORVcnLFxuICAgIFBFTkRJTkcgPSAnUEVORElORycsXG4gICAgUkVKRUNURUQgPSAnUkVKRUNURUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZURvbmF0aW9uUmVzcG9uc2Uge1xuICAgIGFtb3VudDogc3RyaW5nO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICBwcm9kdWN0OiB7XG4gICAgICAgIGN1cnJlbmN5PzogQ3JlYXRlRG9uYXRpb25SZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3RfdHlwZTogQ3JlYXRlRG9uYXRpb25SZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgIH07XG4gICAgc3RhdHVzPzogQ3JlYXRlRG9uYXRpb25SZXNwb25zZVN0YXR1cztcbiAgICBzdGF0dXNfbGVkZ2VyPzogT2JqZWN0O1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL2RvbmF0aW9uLnB5LyNsaW5lcy0xODRcbiAqL1xuXG5leHBvcnQgZW51bSBDcmVhdGVEb25hdGlvbmF0dGVtcHRCb2R5RXZlbnQge1xuICAgIENMT1NFID0gJ0NMT1NFJyxcbiAgICBSRUNBTEwgPSAnUkVDQUxMJyxcbiAgICBTVEFSVCA9ICdTVEFSVCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlRG9uYXRpb25hdHRlbXB0Qm9keSB7XG4gICAgZXZlbnQ6IENyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHlFdmVudDtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9kb25hdGlvbi5weS8jbGluZXMtOFxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlRXZlbnQge1xuICAgIENMT1NFID0gJ0NMT1NFJyxcbiAgICBSRUNBTEwgPSAnUkVDQUxMJyxcbiAgICBTVEFSVCA9ICdTVEFSVCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2Uge1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZXZlbnQ6IENyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlRXZlbnQ7XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBFeHRlcm5hbCBBcHBzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2V4dGVybmFsX2FwcHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEV4dGVybmFsQXBwc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBdXRob3JpemUgYSBnaXZlbiBleHRlcm5hbCBhcHAgdG9rZW5cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDYW4gYmUgY2FsbGVkIGJ5IHRoZSBBUEkgR2F0ZXdheSBpbiBvcmRlciB0byBhdXRob3JpemUgZXZlcnkgcmVxdWVzdCB1c2luZyBwcm92aWRlZCB0b2tlbi4gSXQgbXVzdCBiZSB1c2VkIG9ubHkgZm9yIGV4dGVybmFsIGFwcCB0b2tlbnMsIHdoaWNoIGFyZSB1c2VkIGJ5IHRoZSBleHRlcm5hbCBhcHBzIHRvIG1ha2UgY2FsbHMgb24gYmVoYWxmIG9mIGEgZ2l2ZW4gdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgYXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLkF1dGhvcml6ZUV4dGVybmFsQXBwQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkF1dGhvcml6ZUV4dGVybmFsQXBwQXV0aFRva2VuUmVzcG9uc2U+KCcvZXh0ZXJuYWwvYXV0aF90b2tlbnMvYXV0aG9yaXplLycsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEV4dGVybmFsIEFwcCBDb25maWd1cmF0aW9uXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuUmVzcG9uc2U+KCcvZXh0ZXJuYWwvYXV0aF90b2tlbnMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEV4dGVybmFsIEFwcCBjb25maWd1cmF0aW9uXG4gICAgICovXG4gICAgcHVibGljIHJlYWRFeHRlcm5hbGFwcGNvbmYocGFyYW1zOiBYLlJlYWRFeHRlcm5hbGFwcGNvbmZRdWVyeSk6IERhdGFTdGF0ZTxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPignL2V4dGVybmFsL2FwcHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRFeHRlcm5hbGFwcGNvbmYyKHBhcmFtczogWC5SZWFkRXh0ZXJuYWxhcHBjb25mUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+KCcvZXh0ZXJuYWwvYXBwcy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRm9jdXMgUmVjb3JkcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9mb2N1c19yZWNvcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBGb2N1c1JlY29yZHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEZvY3VzIFJlY29yZFxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVGb2N1c3JlY29yZChib2R5OiBYLkNyZWF0ZUZvY3VzcmVjb3JkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGb2N1c3JlY29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVGb2N1c3JlY29yZFJlc3BvbnNlPignL2ZvY3VzX3JlY29yZHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEZvY3VzIFJlY29yZCBTdW1tYXJ5XG4gICAgICovXG4gICAgcHVibGljIHJlYWRGb2N1c1JlY29yZFN1bW1hcnkoKTogRGF0YVN0YXRlPFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+KCcvZm9jdXNfcmVjb3Jkcy9zdW1tYXJ5LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEZvY3VzUmVjb3JkU3VtbWFyeTIoKTogT2JzZXJ2YWJsZTxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPignL2ZvY3VzX3JlY29yZHMvc3VtbWFyeS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZyYWdtZW50IEhhc2h0YWdzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZyYWdtZW50X2hhc2h0YWdzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBGcmFnbWVudEhhc2h0YWdzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgSGFzaHRhZ3NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IEhhc2h0YWdzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy9oYXNodGFncy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvaGFzaHRhZ3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBIYXNodGFnc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUHVibGlzaGVkIEhhc2h0YWdzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy9oYXNodGFncy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy9oYXNodGFncy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBGcmFnbWVudCBXb3JkcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9mcmFnbWVudF93b3Jkcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRnJhZ21lbnRXb3Jkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFdvcmRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBXb3Jkc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEZyYWdtZW50V29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvd29yZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3dvcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgV29yZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBXb3Jkc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvd29yZHMvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvd29yZHMvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRnJhZ21lbnRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZyYWdtZW50cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRnJhZ21lbnRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgUmVtb3RlIEZyYWdtZW50c1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUmVtb3RlIEZyYWdtZW50c1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEZyYWdtZW50cyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBSZW1vdGUgRnJhZ21lbnRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZyYWdtZW50KCk6IE9ic2VydmFibGU8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPignL2ZyYWdtZW50cy8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZWxldGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRGVsZXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNZXJnZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBNZXJnZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgbWVyZ2VGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguTWVyZ2VGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5NZXJnZUZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vbWVyZ2UvYCwge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHVibGlzaCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBQdWJsaXNoIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBwdWJsaXNoRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlB1Ymxpc2hGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlB1Ymxpc2hGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L3B1Ymxpc2gvYCwge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRnJhZ21lbnQyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEZyYWdtZW50IERpZmZcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIEZyYWdtZW50IERpZmZcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50RGlmZihmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9kaWZmL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50RGlmZjIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L2RpZmYvYCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBGcmFnbWVudCBTYW1wbGVcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIEZyYWdtZW50IFNhbXBsZVxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRnJhZ21lbnRTYW1wbGUoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L3NhbXBsZS9gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRnJhZ21lbnRTYW1wbGUyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vc2FtcGxlL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVGcmFnbWVudChmcmFnbWVudElkOiBhbnksIGJvZHk6IFguVXBkYXRlRnJhZ21lbnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBHZW9tZXRyaWVzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2dlb21ldHJpZXMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEdlb21ldHJpZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBHZW9tZXRyaWVzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBHZW9tZXRyaWVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEdlb21ldHJpZXMocGFyYW1zOiBYLkJ1bGtSZWFkR2VvbWV0cmllc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9ncmlkL2dlb21ldHJpZXMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkR2VvbWV0cmllczIocGFyYW1zOiBYLkJ1bGtSZWFkR2VvbWV0cmllc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+KCcvZ3JpZC9nZW9tZXRyaWVzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQnVsayBVcGRhdGUgR2VvbWV0cmllc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSBpbiBhIEJ1bGsgbGlzdCBvZiBHZW9tZXRyaWVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrVXBkYXRlR2VvbWV0cmllcyhib2R5OiBYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzQm9keSk6IE9ic2VydmFibGU8WC5CdWxrVXBkYXRlR2VvbWV0cmllc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzUmVzcG9uc2U+KCcvZ3JpZC9nZW9tZXRyaWVzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBHZW9tZXRyeSBieSBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBhIEdlb21ldHJ5IGVudGl0eSBnaXZlbiB0aGUgaWQgb2YgQ2FyZCB3aGljaCBpcyB0aGUgcGFyZW50IG9mIHRoZSBHZW9tZXRyeSBlbnRpdHkuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRHZW9tZXRyeUJ5Q2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4oYC9ncmlkL2dlb21ldHJpZXMvYnlfY2FyZC8ke2NhcmRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRHZW9tZXRyeUJ5Q2FyZDIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEdlb21ldHJ5QnlDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPihgL2dyaWQvZ2VvbWV0cmllcy9ieV9jYXJkLyR7Y2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgR3JhcGhcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZW5kZXIgYW5kIHJlYWQgR3JhcGggbWFkZSBvdXQgb2YgYWxsIENhcmRzIGFuZCBMaW5rcyBiZWxvbmdpbmcgdG8gYSBnaXZlbiB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkR3JhcGgocGFyYW1zOiBYLlJlYWRHcmFwaFF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEdyYXBoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRHcmFwaFJlc3BvbnNlPignL2dyaWQvZ3JhcGhzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkR3JhcGgyKHBhcmFtczogWC5SZWFkR3JhcGhRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkR3JhcGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEdyYXBoUmVzcG9uc2U+KCcvZ3JpZC9ncmFwaHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEdvc3NpcCBDb21tYW5kcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9nb3NzaXAubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEdvc3NpcERvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgYWxsIHN1cHBvcnRlZCBzcG9rZW4gbGFuZ3VhZ2VzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRTcGVlY2hMYW5ndWFnZXNSZXNwb25zZUVudGl0eVtdPignL2dvc3NpcC9zcGVlY2gvbGFuZ3VhZ2VzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRTcGVlY2hMYW5ndWFnZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFNwZWVjaExhbmd1YWdlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4oJy9nb3NzaXAvc3BlZWNoL2xhbmd1YWdlcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgYWxsIHN1cHBvcnRlZCB2b2ljZSBsYW5ndWFnZXNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRUZXh0TGFuZ3VhZ2VzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGV4dExhbmd1YWdlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGV4dExhbmd1YWdlc1Jlc3BvbnNlRW50aXR5W10+KCcvZ29zc2lwL3RleHQvbGFuZ3VhZ2VzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRUZXh0TGFuZ3VhZ2VzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUZXh0TGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRUZXh0TGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4oJy9nb3NzaXAvdGV4dC9sYW5ndWFnZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGV0ZWN0IHNwb2tlbiBsYW5ndWFnZVxuICAgICAqL1xuICAgIHB1YmxpYyBkZXRlY3RTcGVlY2hMYW5ndWFnZXMoYm9keTogWC5EZXRlY3RTcGVlY2hMYW5ndWFnZXNCb2R5KTogT2JzZXJ2YWJsZTxYLkRldGVjdFNwZWVjaExhbmd1YWdlc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5EZXRlY3RTcGVlY2hMYW5ndWFnZXNSZXNwb25zZT4oJy9nb3NzaXAvc3BlZWNoL2RldGVjdF9sYW5ndWFnZXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZXRlY3Qgd3JpdHRlbiBsYW5ndWFnZVxuICAgICAqL1xuICAgIHB1YmxpYyBkZXRlY3RUZXh0TGFuZ3VhZ2VzKGJvZHk6IFguRGV0ZWN0VGV4dExhbmd1YWdlc0JvZHkpOiBPYnNlcnZhYmxlPFguRGV0ZWN0VGV4dExhbmd1YWdlc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5EZXRlY3RUZXh0TGFuZ3VhZ2VzUmVzcG9uc2U+KCcvZ29zc2lwL3RleHQvZGV0ZWN0X2xhbmd1YWdlcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogSGFzaHRhZ3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vaGFzaHRhZ3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEhhc2h0YWdzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgSGFzaHRhZ3NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBsaXN0IGEgc2VyaWVzIG9mIEhhc2h0YWcgaW5zdGFuY2VzLiBJdCBhY2NlcHRzIHZhcmlvdXMgcXVlcnkgcGFyYW1ldGVycyBzdWNoIGFzOiAtIGBsaW1pdGAgLSBgb2Zmc2V0YCAtIGBmaXJzdF9jaGFyYWN0ZXJgXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkSGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9oYXNodGFncy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvaGFzaHRhZ3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGluZyBhIHNpbmdsZSBIYXNodGFnXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY3JlYXRlIGEgc2luZ2xlIEhhc2h0YWcgaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUhhc2h0YWcoYm9keTogWC5DcmVhdGVIYXNodGFnQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVIYXNodGFnUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUhhc2h0YWdSZXNwb25zZT4oJy9oYXNodGFncy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92aW5nIGEgc2luZ2xlIEhhc2h0YWdcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBkZXRhY2ggYSBzaW5nbGUgSGFzaHRhZyBpbnN0YW5jZSBmcm9tIGEgbGlzdCBjYXJkcyBnaXZlbiBieSBgY2FyZF9pZHNgLlxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVIYXNodGFnKGhhc2h0YWdJZDogYW55LCBwYXJhbXM6IFguRGVsZXRlSGFzaHRhZ1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVIYXNodGFnUmVzcG9uc2U+KGAvaGFzaHRhZ3MvJHtoYXNodGFnSWR9YCwgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgSGFzaHRhZ3MgVE9DXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gbGlzdCBIYXNodGFncyBUYWJsZSBvZiBDb250ZW50cyBtYWRlIG91dCBvZiBIYXNodGFncy4gTm90ZTogQ3VycmVudGx5IHRoaXMgZW5kcG9pbnQgcmV0dXJucyBvbmx5IGEgZmxhdCBsaXN0IG9mIGhhc2h0YWdzIHdpdGggdGhlIGNvdW50IG9mIENhcmRzIHdpdGggd2hpY2ggdGhleSdyZSBhdHRhY2hlZCB0by4gSW4gdGhlIGZ1dHVyZSB0aG91Z2ggb25lIGNvdWxkIHByb3Bvc2UgYSBtZWNoYW5pc20gd2hpY2ggY291bGQgY2FsY3VsYXRlIGhpZXJhcmNoeSBiZXR3ZWVuIHRob3NlIGhhc2h0YWdzIChwYXJlbnQgLSBjaGlsZCByZWxhdGlvbnNoaXBzKSBhbmQgb3JkZXJpbmcgYmFzZWQgb24gdGhlIGtub3dsZWRnZSBncmlkIHRvcG9sb2d5LiBJdCBhY2NlcHRzIHZhcmlvdXMgcXVlcnkgcGFyYW1ldGVycyBzdWNoIGFzOiAtIGBsaW1pdGAgLSBgb2Zmc2V0YFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkSGFzaHRhZ3NUb2MocGFyYW1zOiBYLlJlYWRIYXNodGFnc1RvY1F1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPignL2hhc2h0YWdzL3RvYy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEhhc2h0YWdzVG9jMihwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPignL2hhc2h0YWdzL3RvYy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0aW5nIGEgc2luZ2xlIEhhc2h0YWdcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byB1cGRhdGUgYSBzaW5nbGUgSGFzaHRhZyBpbnN0YW5jZSB3aXRoIGEgbGlzdCBvZiBgY2FyZF9pZHNgIHRvIHdoaWNoIGl0IHNob3VsZCBnZXQgYXR0YWNoZWQgdG8uXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIGJvZHk6IFguVXBkYXRlSGFzaHRhZ0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZUhhc2h0YWdSZXNwb25zZT4oYC9oYXNodGFncy8ke2hhc2h0YWdJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogSW52b2ljZSBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9pbnZvaWNlcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSW52b2ljZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBhbGwgSW52b2ljZXMgYmVsb25naW5nIHRvIGEgZ2l2ZW4gdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIGxpc3QgYWxsIG9mIHRoZSBJbnZvaWNlcyB3aGljaCB3ZXJlIGdlbmVyYXRlZCBmb3IgaGlzIERvbmF0aW9ucyBvciBTdWJzY3JpcHRpb24gcGF5bWVudHMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkSW52b2ljZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUVudGl0eVtdPignL3BheW1lbnRzL2ludm9pY2VzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRJbnZvaWNlczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXltZW50cy9pbnZvaWNlcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYWxjdWxhdGUgZGVidCBmb3IgYSBnaXZlbiB1c2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQ2FsY3VsYXRlIGRlYnQgZm9yIGEgZ2l2ZW4gdXNlciBieSBzZWFyY2hpbmcgZm9yIHRoZSBsYXRlc3QgdW5wYWlkIGludm9pY2UuIEl0IHJldHVybnMgcGF5bWVudCB0b2tlbiB3aGljaCBjYW4gYmUgdXNlZCBpbiB0aGUgUEFJRF9XSVRIX0RFRkFVTFRfUEFZTUVOVF9DQVJEIGNvbW1hbmRcbiAgICAgKi9cbiAgICBwdWJsaWMgY2FsY3VsYXRlRGVidCgpOiBEYXRhU3RhdGU8WC5DYWxjdWxhdGVEZWJ0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4oJy9wYXltZW50cy9pbnZvaWNlcy9kZWJ0LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgY2FsY3VsYXRlRGVidDIoKTogT2JzZXJ2YWJsZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQ2FsY3VsYXRlRGVidFJlc3BvbnNlPignL3BheW1lbnRzL2ludm9pY2VzL2RlYnQvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBJbnZvaWNlIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvaW52b2ljZS5weS8jbGluZXMtNTNcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBhbW91bnQ6IHN0cmluZztcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGN1cnJlbmN5Pzogc3RyaW5nO1xuICAgIGRpc3BsYXlfYW1vdW50OiBzdHJpbmc7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgaXNfZXh0ZW5zaW9uPzogYm9vbGVhbjtcbiAgICBwYWlkX3RpbGxfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgcHJvZHVjdDoge1xuICAgICAgICBjdXJyZW5jeT86IEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3RfdHlwZTogQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgfTtcbiAgICBzdXJwbHVzX2Ftb3VudD86IHN0cmluZztcbiAgICBzdXJwbHVzX2N1cnJlbmN5Pzogc3RyaW5nO1xuICAgIHZhbGlkX3RpbGxfdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlIHtcbiAgICBpbnZvaWNlczogQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvaW52b2ljZS5weS8jbGluZXMtNTFcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENhbGN1bGF0ZURlYnRSZXNwb25zZSB7XG4gICAgYXRfX2NvbW1hbmRzOiBPYmplY3Q7XG4gICAgY3VycmVuY3k6IHN0cmluZztcbiAgICBkaXNwbGF5X293ZXM6IHN0cmluZztcbiAgICBvd2VzOiBudW1iZXI7XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBMaW5rcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9saW5rcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTGlua3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIExpbmtcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZW1vdmUgYSBMaW5rIGJldHdlZW4gdHdvIGNhcmRzLlxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVMaW5rKGZyb21DYXJkSWQ6IGFueSwgdG9DYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVMaW5rUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlTGlua1Jlc3BvbnNlPihgL2dyaWQvbGlua3MvJHtmcm9tQ2FyZElkfS8ke3RvQ2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBvciBDcmVhdGUgTGlua1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgb3IgQ3JlYXRlIGEgTGluayBiZXR3ZWVuIHR3byBjYXJkcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE9yQ3JlYXRlTGluayhib2R5OiBYLlJlYWRPckNyZWF0ZUxpbmtCb2R5KTogT2JzZXJ2YWJsZTxYLlJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlPignL2dyaWQvbGlua3MvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIExpbmtzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvNWYyMTVmYWJiYTdmYTM5MjUxNTFjMDk4ZmFkMDA1MTE2MjQ1MjgyMS8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRGVsZXRlTGlua1Jlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvNWYyMTVmYWJiYTdmYTM5MjUxNTFjMDk4ZmFkMDA1MTE2MjQ1MjgyMS9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS9ncmlkL3ZpZXdzLnB5LyNsaW5lcy00OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVhZE9yQ3JlYXRlTGlua0JvZHkge1xuICAgIGZyb21fY2FyZF9pZDogbnVtYmVyO1xuICAgIHRvX2NhcmRfaWQ6IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy81ZjIxNWZhYmJhN2ZhMzkyNTE1MWMwOThmYWQwMDUxMTYyNDUyODIxL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL2dyaWQvc2VyaWFsaXplcnMucHkvI2xpbmVzLThcbiAqL1xuXG5leHBvcnQgZW51bSBSZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2VLaW5kIHtcbiAgICBDQVJEID0gJ0NBUkQnLFxuICAgIEZSQUdNRU5UID0gJ0ZSQUdNRU5UJyxcbiAgICBIQVNIVEFHID0gJ0hBU0hUQUcnLFxuICAgIFBBVEggPSAnUEFUSCcsXG4gICAgVEVSTSA9ICdURVJNJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBSZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2Uge1xuICAgIGF1dGhvcl9pZD86IGFueTtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGZyb21fY2FyZF9pZD86IGFueTtcbiAgICBpZD86IG51bWJlcjtcbiAgICBraW5kOiBSZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2VLaW5kO1xuICAgIHJlZmVyZW5jZV9pZDogbnVtYmVyO1xuICAgIHRvX2NhcmRfaWQ/OiBhbnk7XG4gICAgdmFsdWU6IG51bWJlcjtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIE1lZGlhSXRlbXMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vbWVkaWFpdGVtcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTWVkaWFpdGVtc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IE1lZGlhSXRlbXNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IE1lZGlhSXRlbXNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRNZWRpYWl0ZW1zKHBhcmFtczogWC5CdWxrUmVhZE1lZGlhaXRlbXNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkTWVkaWFpdGVtc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkTWVkaWFpdGVtc1Jlc3BvbnNlRW50aXR5W10+KCcvbWVkaWFpdGVtcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRNZWRpYWl0ZW1zMihwYXJhbXM6IFguQnVsa1JlYWRNZWRpYWl0ZW1zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4oJy9tZWRpYWl0ZW1zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIE1lZGlhSXRlbVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbW92ZSBNZWRpYUl0ZW0gaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55LCBwYXJhbXM6IFguRGVsZXRlTWVkaWFpdGVtUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlTWVkaWFpdGVtUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy8ke21lZGlhaXRlbUlkfWAsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIE1lZGlhSXRlbVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgTWVkaWFJdGVtXG4gICAgICovXG4gICAgcHVibGljIHJlYWRNZWRpYWl0ZW0obWVkaWFpdGVtSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPihgL21lZGlhaXRlbXMvJHttZWRpYWl0ZW1JZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRNZWRpYWl0ZW0yKG1lZGlhaXRlbUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy8ke21lZGlhaXRlbUlkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgQnkgUHJvY2VzcyBJZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgTWVkaWFJdGVtIGJ5IFByb2Nlc3MgSWRcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkKCk6IERhdGFTdGF0ZTxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWRSZXNwb25zZT4oJy9tZWRpYWl0ZW1zL2J5X3Byb2Nlc3MvKD9QPHByb2Nlc3NfaWQ+W1xcdytcXD1dKyknLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZDIoKTogT2JzZXJ2YWJsZTxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWRSZXNwb25zZT4oJy9tZWRpYWl0ZW1zL2J5X3Byb2Nlc3MvKD9QPHByb2Nlc3NfaWQ+W1xcdytcXD1dKyknLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIG9yIENyZWF0ZSBNZWRpYUl0ZW1cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIG9yIENyZWF0ZSBNZWRpYUl0ZW0gaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRPckNyZWF0ZU1lZGlhaXRlbShib2R5OiBYLlJlYWRPckNyZWF0ZU1lZGlhaXRlbUJvZHkpOiBPYnNlcnZhYmxlPFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlJlYWRPckNyZWF0ZU1lZGlhaXRlbVJlc3BvbnNlPignL21lZGlhaXRlbXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgTWVkaWFJdGVtXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIE1lZGlhSXRlbSBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnksIGJvZHk6IFguVXBkYXRlTWVkaWFpdGVtQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVNZWRpYWl0ZW1SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgTWVkaWFJdGVtIFJlcHJlc2VudGF0aW9uXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIGdpdmVuIE1lZGlhSXRlbSB3aXRoIG9ubHkgdGhlIGZpZWxkcyB3aGljaCBhcmUgZGVjaWRlZCBleHRlcm5hbGx5ICh1c2luZyBleHRlcm5hbCBzZXJ2aWNlcykuIEZpZWxkcyBsaWtlOiAtIGB3ZWJfcmVwcmVzZW50YXRpb25zYCAtIGB0aHVtYm5haWxfdXJpYCAtIGBtZXRhYCAtIGB0ZXh0YCBBbGwgb2YgdGhvc2UgZmllbGRzIGFyZSBjb21wdXRlZCBpbiBzbWFydGVyIHdheSBpbiBvcmRlciB0byBtYWtlIHRoZSBNZWRpYUl0ZW0gd2F5IGJldHRlciBpbiBhIHNlbWFudGljIHNlbnNlLiBUaG9zZSBmaWVsZHMgYXJlIHBlcmNlaXZlZCBhcyB0aGUgYHJlcHJlc2VudGF0aW9uYCBvZiBhIGdpdmVuIE1lZGlhSXRlbSBzaW5jZSB0aGV5IGNvbnRhaW5zIGluZm9ybWF0aW9uIGFib3V0IGhvdyB0byBkaXNwbGF5IGEgZ2l2ZW4gTWVkaWFJdGVtLCBob3cgdG8gdW5kZXJzdGFuZCBpdCBldGMuIEl0IGdvZXMgYmV5b25kIHRoZSBzaW1wbGUgYWJzdHJhY3QgZGF0YSBvcmllbnRlZCByZXByZXNlbnRhdGlvbiAodXJpLCBleHRlbnNpb24gZXRjLikuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uKG1lZGlhaXRlbUlkOiBhbnksIGJvZHk6IFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9L3JlcHJlc2VudGF0aW9uL2AsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBOb3RpZmljYXRpb24gTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vbm90aWZpY2F0aW9ucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTm90aWZpY2F0aW9uc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBY2tub3dsZWRnZSBOb3RpZmljYXRpb25cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBBY2tub3dsZWRnZSBOb3RpZmljYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgYWNrbm93bGVkZ2VOb3RpZmljYXRpb24obm90aWZpY2F0aW9uSWQ6IGFueSk6IE9ic2VydmFibGU8WC5BY2tub3dsZWRnZU5vdGlmaWNhdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLkFja25vd2xlZGdlTm90aWZpY2F0aW9uUmVzcG9uc2U+KGAvbm90aWZpY2F0aW9ucy8ke25vdGlmaWNhdGlvbklkfS9hY2tub3dsZWRnZS9gLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IE5vdGlmaWNhdGlvbnNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IE5vdGlmaWNhdGlvbnNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWROb3RpZmljYXRpb25zKHBhcmFtczogWC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W10+KCcvbm90aWZpY2F0aW9ucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWROb3RpZmljYXRpb25zMihwYXJhbXM6IFguQnVsa1JlYWROb3RpZmljYXRpb25zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4oJy9ub3RpZmljYXRpb25zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBOb3RpZmljYXRpb24gTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWZyYWdtZW50LXNlcnZpY2Uvc3JjLzM3MDliNTJlNmQ3YzczOTkxNTQ1ODJlODA1NWMwZTc2MTM5YTRjMDAvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEFja25vd2xlZGdlTm90aWZpY2F0aW9uUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWZyYWdtZW50LXNlcnZpY2Uvc3JjLzM3MDliNTJlNmQ3YzczOTkxNTQ1ODJlODA1NWMwZTc2MTM5YTRjMDAvY29zcGhlcmVfZnJhZ21lbnRfc2VydmljZS9ub3RpZmljYXRpb24vdmlld3MucHkvI2xpbmVzLTc3XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSB7XG4gICAgYWNrbm93bGVkZ2VkPzogYm9vbGVhbjtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcF9fZ3Q/OiBudW1iZXI7XG4gICAgbGltaXQ/OiBudW1iZXI7XG4gICAgb2Zmc2V0PzogbnVtYmVyO1xuICAgIHVwZGF0ZWRfdGltZXN0YW1wX19ndD86IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWZyYWdtZW50LXNlcnZpY2Uvc3JjLzM3MDliNTJlNmQ3YzczOTkxNTQ1ODJlODA1NWMwZTc2MTM5YTRjMDAvY29zcGhlcmVfZnJhZ21lbnRfc2VydmljZS9ub3RpZmljYXRpb24vc2VyaWFsaXplcnMucHkvI2xpbmVzLTQ2XG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VLaW5kIHtcbiAgICBGUkFHTUVOVF9VUERBVEUgPSAnRlJBR01FTlRfVVBEQVRFJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eSB7XG4gICAgYWNrbm93bGVkZ2VkOiBib29sZWFuO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAga2luZDogQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VLaW5kO1xuICAgIHBheWxvYWQ6IE9iamVjdDtcbiAgICB1cGRhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlIHtcbiAgICBub3RpZmljYXRpb25zOiBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogTm91bnMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vbm91bnMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIE5vdW5zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBOb3VuIFByb2plY3QgSWNvbnNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRJY29ucyhwYXJhbXM6IFguQnVsa1JlYWRJY29uc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRJY29uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkSWNvbnNSZXNwb25zZUVudGl0eVtdPignL25vdW5zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEljb25zMihwYXJhbXM6IFguQnVsa1JlYWRJY29uc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSWNvbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEljb25zUmVzcG9uc2VFbnRpdHlbXT4oJy9ub3Vucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUGF0aHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcGF0aHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFBhdGhzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIERlbGV0ZSBQYXRoc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuZHBvaW50IGZvciBEZWxldGluZyBtdWx0aXBsZSBQYXRocy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa0RlbGV0ZVBhdGhzKHBhcmFtczogWC5CdWxrRGVsZXRlUGF0aHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrRGVsZXRlUGF0aHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5CdWxrRGVsZXRlUGF0aHNSZXNwb25zZT4oJy9wYXRocy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBQYXRoc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgYWxsIHVzZXIncyBQYXRoc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFBhdGhzKHBhcmFtczogWC5CdWxrUmVhZFBhdGhzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+KCcvcGF0aHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUGF0aHMyKHBhcmFtczogWC5CdWxrUmVhZFBhdGhzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPignL3BhdGhzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIFBhdGhcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmRwb2ludCBmb3IgQ3JlYXRpbmcgUGF0aC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlUGF0aChib2R5OiBYLkNyZWF0ZVBhdGhCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlUGF0aFJlc3BvbnNlPignL3BhdGhzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBQYXRoXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBzaW5nbGUgUGF0aFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkUGF0aChwYXRoSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRQYXRoUmVzcG9uc2U+KGAvcGF0aHMvJHtwYXRoSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkUGF0aDIocGF0aElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZFBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZFBhdGhSZXNwb25zZT4oYC9wYXRocy8ke3BhdGhJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgUGF0aFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuZHBvaW50IGZvciBVcGRhdGluZyBQYXRoLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVQYXRoKHBhdGhJZDogYW55LCBib2R5OiBYLlVwZGF0ZVBhdGhCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVQYXRoUmVzcG9uc2U+KGAvcGF0aHMvJHtwYXRoSWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFBheW1lbnQgQ2FyZHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcGF5bWVudF9jYXJkcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUGF5bWVudENhcmRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIE1hcmsgYSBnaXZlbiBQYXltZW50IENhcmQgYXMgYSBkZWZhdWx0IG9uZVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIG1hcmsgYSBzcGVjaWZpYyBQYXltZW50IENhcmQgYXMgYSBkZWZhdWx0IG9uZSwgbWVhbmluZyB0aGF0IGl0IHdpbGwgYmUgdXNlZCBmb3IgYWxsIHVwY29taW5nIHBheW1lbnRzLiBNYXJraW5nIFBheW1lbnQgQ2FyZCBhcyBhIGRlZmF1bHQgb25lIGF1dG9tYXRpY2FsbHkgbGVhZHMgdG8gdGhlIHVubWFya2luZyBvZiBhbnkgUGF5bWVudCBDYXJkIHdoaWNoIHdhcyBkZWZhdWx0IG9uZSBiZWZvcmUgdGhlIGludm9jYXRpb24gb2YgdGhlIGNvbW1hbmQuXG4gICAgICovXG4gICAgcHVibGljIGFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZChwYXltZW50Q2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguQXNEZWZhdWx0TWFya1BheW1lbnRjYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguQXNEZWZhdWx0TWFya1BheW1lbnRjYXJkUmVzcG9uc2U+KGAvcGF5bWVudHMvcGF5bWVudF9jYXJkcy8ke3BheW1lbnRDYXJkSWR9L21hcmtfYXNfZGVmYXVsdC9gLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IGFsbCBQYXltZW50IENhcmRzIGJlbG9uZ2luZyB0byBhIGdpdmVuIHVzZXJcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIHRoZSB0aGUgVXNlciB0byBsaXN0IGFsbCBvZiB0aGUgUGF5bWVudCBDYXJkcyB3aGljaCB3ZXJlIGFkZGVkIGJ5IGhpbSAvIGhlci4gQW1vbmcgYWxsIHJldHVybmVkIFBheW1lbnQgQ2FyZHMgdGhlcmUgbXVzdCBiZSBvbmUgYW5kIG9ubHkgb25lIHdoaWNoIGlzIG1hcmtlZCBhcyAqKmRlZmF1bHQqKi5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRQYXltZW50Y2FyZHMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+KCcvcGF5bWVudHMvcGF5bWVudF9jYXJkcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUGF5bWVudGNhcmRzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+KCcvcGF5bWVudHMvcGF5bWVudF9jYXJkcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgYSBQYXltZW50IENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIHRoZSB0aGUgVXNlciB0byBhZGQgbmV3IFBheW1lbnQgQ2FyZCwgd2hpY2ggY291bGQgYmUgbmVlZGVkIGluIGNhc2VzIHdoZW4gdGhlIFVzZXIgd291bGQgbGlrZSB0byByZXBsYWNlIGV4aXN0aW5nIFBheW1lbnQgQ2FyZCBiZWNhdXNlOiAtIGl0IGV4cGlyZWQgLSBpcyBlbXB0eSAtIHRoZSBVc2VyIHByZWZlcnMgYW5vdGhlciBvbmUgdG8gYmUgdXNlZCBmcm9tIG5vdyBvbi4gVXNpbmcgdGhlIG9wdGlvbmFsIGBtYXJrX2FzX2RlZmF1bHRgIGZpZWxkIG9uZSBjYW4gbWFyayBqdXN0IGNyZWF0ZWQgUGF5bWVudCBDYXJkIGFzIHRoZSBkZWZhdWx0IG9uZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlUGF5bWVudGNhcmQoYm9keTogWC5DcmVhdGVQYXltZW50Y2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIGEgZ2l2ZW4gUGF5bWVudCBDYXJkIGJlbG9uZ2luZyB0byBhIGdpdmVuIHVzZXJcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIHRoZSB0aGUgVXNlciB0byByZW1vdmUgYSBzcGVjaWZpYyBQYXltZW50IENhcmQgd2hpY2ggd2VyZSBhZGRlZCBieSBoaW0gLyBoZXIuIFBheW1lbnQgQ2FyZCBjYW4gYmUgcmVtb3ZlZCBvbmx5IGlmIGl0J3Mgbm90IGEgZGVmYXVsdCBvbmUuXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZVBheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkRlbGV0ZVBheW1lbnRjYXJkUmVzcG9uc2U+KGAvcGF5bWVudHMvcGF5bWVudF9jYXJkcy8ke3BheW1lbnRDYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQYXkgdXNpbmcgdGhlIGRlZmF1bHQgUGF5bWVudCBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXNlciBpcyBhbGxvd2VkIG9ubHkgdG8gcGVyZm9ybSBwYXltZW50cyBhZ2FpbnN0IGhlciBkZWZhdWx0IFBheW1lbnQgQ2FyZC4gSW4gb3RoZXIgd29yZHMgb24gb3JkZXIgdG8gdXNlIGEgZ2l2ZW4gUGF5bWVudCBDYXJkIG9uZSBoYXMgdG8gbWFyayBpcyBhcyBkZWZhdWx0LiBBbHNvIG9uZSBpcyBub3QgYWxsb3dlZCB0byBwZXJmb3JtIHN1Y2ggcGF5bWVudHMgZnJlZWx5IGFuZCB0aGVyZWZvcmUgd2UgZXhwZWN0IHRvIGdldCBhIGBwYXltZW50X3Rva2VuYCBpbnNpZGUgd2hpY2ggYW5vdGhlciBwaWVjZSBvZiBvdXIgc3lzdGVtIGVuY29kZWQgYWxsb3dlZCBzdW0gdG8gYmUgcGFpZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgcGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZChib2R5OiBYLlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlPignL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvcGF5X3dpdGhfZGVmYXVsdC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIFBheW1lbnQgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIGFkZCBuZXcgUGF5bWVudCBDYXJkLCB3aGljaCBjb3VsZCBiZSBuZWVkZWQgaW4gY2FzZXMgd2hlbiB0aGUgVXNlciB3b3VsZCBsaWtlIHRvIHJlcGxhY2UgZXhpc3RpbmcgUGF5bWVudCBDYXJkIGJlY2F1c2U6IC0gaXQgZXhwaXJlZCAtIGlzIGVtcHR5IC0gdGhlIFVzZXIgcHJlZmVycyBhbm90aGVyIG9uZSB0byBiZSB1c2VkIGZyb20gbm93IG9uXG4gICAgICovXG4gICAgcHVibGljIHJlbmRlclBheW1lbnRDYXJkV2lkZ2V0KCk6IERhdGFTdGF0ZTxYLlJlbmRlclBheW1lbnRDYXJkV2lkZ2V0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlbmRlclBheW1lbnRDYXJkV2lkZ2V0UmVzcG9uc2U+KCcvcGF5bWVudHMvcGF5bWVudF9jYXJkcy93aWRnZXQvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZW5kZXJQYXltZW50Q2FyZFdpZGdldDIoKTogT2JzZXJ2YWJsZTxYLlJlbmRlclBheW1lbnRDYXJkV2lkZ2V0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlbmRlclBheW1lbnRDYXJkV2lkZ2V0UmVzcG9uc2U+KCcvcGF5bWVudHMvcGF5bWVudF9jYXJkcy93aWRnZXQvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBQYXltZW50IENhcmRzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvcGF5bWVudF9jYXJkLnB5LyNsaW5lcy03NVxuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgZW51bSBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlU3RhdHVzIHtcbiAgICBDQU5DRUxFRCA9ICdDQU5DRUxFRCcsXG4gICAgQ09NUExFVEVEID0gJ0NPTVBMRVRFRCcsXG4gICAgTkVXID0gJ05FVycsXG4gICAgUEVORElORyA9ICdQRU5ESU5HJyxcbiAgICBSRUpFQ1RFRCA9ICdSRUpFQ1RFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eSB7XG4gICAgZXhwaXJhdGlvbl9tb250aD86IG51bWJlcjtcbiAgICBleHBpcmF0aW9uX3llYXI/OiBudW1iZXI7XG4gICAgZXhwaXJlZDogYm9vbGVhbjtcbiAgICBpZD86IG51bWJlcjtcbiAgICBpc19kZWZhdWx0PzogYm9vbGVhbjtcbiAgICBpc19mdWxseV9kZWZpbmVkOiBib29sZWFuO1xuICAgIG1hc2tlZF9udW1iZXI6IHN0cmluZztcbiAgICBwYXltZW50czoge1xuICAgICAgICBhbW91bnQ6IHN0cmluZztcbiAgICAgICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICAgICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICAgICAgcHJvZHVjdDoge1xuICAgICAgICAgICAgY3VycmVuY3k/OiBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgICAgIHByb2R1Y3RfdHlwZTogQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgICAgICB9O1xuICAgICAgICBzdGF0dXM/OiBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlU3RhdHVzO1xuICAgICAgICBzdGF0dXNfbGVkZ2VyPzogT2JqZWN0O1xuICAgIH1bXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlIHtcbiAgICBwYXltZW50X2NhcmRzOiBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvcGF5bWVudF9jYXJkLnB5LyNsaW5lcy01MlxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlUGF5bWVudGNhcmRCb2R5IHtcbiAgICBleHBpcmF0aW9uX21vbnRoOiBudW1iZXI7XG4gICAgZXhwaXJhdGlvbl95ZWFyOiBudW1iZXI7XG4gICAgbWFya19hc19kZWZhdWx0PzogYm9vbGVhbjtcbiAgICBtYXNrZWRfbnVtYmVyOiBzdHJpbmc7XG4gICAgdG9rZW46IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9wYXltZW50X2NhcmQucHkvI2xpbmVzLTlcbiAqL1xuXG5leHBvcnQgZW51bSBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlQ3VycmVuY3kge1xuICAgIFBMTiA9ICdQTE4nLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZVN0YXR1cyB7XG4gICAgQ0FOQ0VMRUQgPSAnQ0FOQ0VMRUQnLFxuICAgIENPTVBMRVRFRCA9ICdDT01QTEVURUQnLFxuICAgIE5FVyA9ICdORVcnLFxuICAgIFBFTkRJTkcgPSAnUEVORElORycsXG4gICAgUkVKRUNURUQgPSAnUkVKRUNURUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2Uge1xuICAgIGV4cGlyYXRpb25fbW9udGg/OiBudW1iZXI7XG4gICAgZXhwaXJhdGlvbl95ZWFyPzogbnVtYmVyO1xuICAgIGV4cGlyZWQ6IGJvb2xlYW47XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgaXNfZGVmYXVsdD86IGJvb2xlYW47XG4gICAgaXNfZnVsbHlfZGVmaW5lZDogYm9vbGVhbjtcbiAgICBtYXNrZWRfbnVtYmVyOiBzdHJpbmc7XG4gICAgcGF5bWVudHM6IHtcbiAgICAgICAgYW1vdW50OiBzdHJpbmc7XG4gICAgICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgICAgIGRpc3BsYXlfYW1vdW50OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgICAgIGN1cnJlbmN5PzogQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICAgICAgZGlzcGxheV9wcmljZTogc3RyaW5nO1xuICAgICAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgICAgICBwcm9kdWN0X3R5cGU6IENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VQcm9kdWN0VHlwZTtcbiAgICAgICAgfTtcbiAgICAgICAgc3RhdHVzPzogQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZVN0YXR1cztcbiAgICAgICAgc3RhdHVzX2xlZGdlcj86IE9iamVjdDtcbiAgICB9W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzY5YmI1NWIwNDcxMzg0NmZjM2FhMWExYzMwMGE4YTllZDIwN2IyZDMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIERlbGV0ZVBheW1lbnRjYXJkUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9wYXltZW50X2NhcmQucHkvI2xpbmVzLTIwNFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZEJvZHkge1xuICAgIHBheW1lbnRfdG9rZW46IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9wYXltZW50LnB5LyNsaW5lcy05XG4gKi9cblxuZXhwb3J0IGVudW0gUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlQ3VycmVuY3kge1xuICAgIFBMTiA9ICdQTE4nLFxufVxuXG5leHBvcnQgZW51bSBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgZW51bSBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VTdGF0dXMge1xuICAgIENBTkNFTEVEID0gJ0NBTkNFTEVEJyxcbiAgICBDT01QTEVURUQgPSAnQ09NUExFVEVEJyxcbiAgICBORVcgPSAnTkVXJyxcbiAgICBQRU5ESU5HID0gJ1BFTkRJTkcnLFxuICAgIFJFSkVDVEVEID0gJ1JFSkVDVEVEJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2Uge1xuICAgIGFtb3VudDogc3RyaW5nO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICBwcm9kdWN0OiB7XG4gICAgICAgIGN1cnJlbmN5PzogUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgcHJvZHVjdF90eXBlOiBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VQcm9kdWN0VHlwZTtcbiAgICB9O1xuICAgIHN0YXR1cz86IFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVN0YXR1cztcbiAgICBzdGF0dXNfbGVkZ2VyPzogT2JqZWN0O1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L21vZGVscy9wYXl1LnB5LyNsaW5lcy0zMTNcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFJlbmRlclBheW1lbnRDYXJkV2lkZ2V0UmVzcG9uc2Uge1xuICAgIGN1cnJlbmN5X2NvZGU6IHN0cmluZztcbiAgICBjdXN0b21lcl9lbWFpbD86IHN0cmluZztcbiAgICBjdXN0b21lcl9sYW5ndWFnZTogc3RyaW5nO1xuICAgIG1lcmNoYW50X3Bvc19pZDogc3RyaW5nO1xuICAgIHJlY3VycmluZ19wYXltZW50OiBib29sZWFuO1xuICAgIHNob3BfbmFtZTogc3RyaW5nO1xuICAgIHNpZzogc3RyaW5nO1xuICAgIHN0b3JlX2NhcmQ6IGJvb2xlYW47XG4gICAgdG90YWxfYW1vdW50OiBzdHJpbmc7XG4gICAgd2lkZ2V0X21vZGU/OiBzdHJpbmc7XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBQYXltZW50cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9wYXltZW50cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUGF5bWVudHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIHRoZSBzdGF0dXMgb2YgYSBnaXZlbiBQYXltZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIHRoZSBQYXltZW50IGluc3RhbmNlIGlkZW50aWZpZWQgYnkgdGhlIGBzZXNzaW9uX2lkYC4gVGhpcyBjb21tYW5kIGlzIGZvciBleHRlcm5hbCB1c2Ugb25seSB0aGVyZWZvcmUgaXQgZG9lc24ndCBleHBvc2UgaW50ZXJuYWwgaWRzIG9mIHRoZSBwYXltZW50cyBidXQgcmF0aGVyIHNlc3Npb24gaWQuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZVBheW1lbnRTdGF0dXMoYm9keTogWC5VcGRhdGVQYXltZW50U3RhdHVzQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVQYXltZW50U3RhdHVzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlVwZGF0ZVBheW1lbnRTdGF0dXNSZXNwb25zZT4oJy9wYXltZW50cy8oP1A8c2Vzc2lvbl9pZD5bXFx3XFwtXSspJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBQcm9jZXNzZXMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcHJvY2Vzc2VzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBQcm9jZXNzZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIERlbGV0aW9uIFByb2Nlc3NcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRGVsZXRpb25Qcm9jZXNzKGJvZHk6IFguQ3JlYXRlRGVsZXRpb25Qcm9jZXNzQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEZWxldGlvblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRGVsZXRpb25Qcm9jZXNzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvZGVsZXRpb25zLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIERvd25sb2FkIFByb2Nlc3NcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRG93bmxvYWRQcm9jZXNzKGJvZHk6IFguQ3JlYXRlRG93bmxvYWRQcm9jZXNzQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEb3dubG9hZFByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRG93bmxvYWRQcm9jZXNzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvZG93bmxvYWRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1lZGlhIExvY2tcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlTWVkaWFMb2NrKGJvZHk6IFguQ3JlYXRlTWVkaWFMb2NrQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVNZWRpYUxvY2tSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlTWVkaWFMb2NrUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9sb2Nrcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBVcGxvYWQgUHJvY2Vzc1xuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVVcGxvYWRQcm9jZXNzKGJvZHk6IFguQ3JlYXRlVXBsb2FkUHJvY2Vzc0JvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlVXBsb2FkUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVVcGxvYWRQcm9jZXNzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvdXBsb2Fkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgaW52YXJpYW50cyBmb3IgYSBnaXZlbiB1cmlcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEludmFyaWFudHMocGFyYW1zOiBYLlJlYWRJbnZhcmlhbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkSW52YXJpYW50c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkSW52YXJpYW50c1Jlc3BvbnNlPignL21lZGlhZmlsZXMvaW52YXJpYW50cy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEludmFyaWFudHMyKHBhcmFtczogWC5SZWFkSW52YXJpYW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRJbnZhcmlhbnRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRJbnZhcmlhbnRzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9pbnZhcmlhbnRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1lZGlhIExvY2tcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZFByb2Nlc3NTdGF0ZShwYXJhbXM6IFguUmVhZFByb2Nlc3NTdGF0ZVF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZFByb2Nlc3NTdGF0ZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRQcm9jZXNzU3RhdGUyKHBhcmFtczogWC5SZWFkUHJvY2Vzc1N0YXRlUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZFByb2Nlc3NTdGF0ZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTaWduIFByb2Nlc3MgZGVkaWNhdGVkIHRvIHVwbG9hZCBhbmQgY29udmVyc2lvbiBvZiBtZWRpYSBmaWxlXG4gICAgICovXG4gICAgcHVibGljIHNpZ25Qcm9jZXNzKHBhcmFtczogWC5TaWduUHJvY2Vzc1F1ZXJ5KTogRGF0YVN0YXRlPFguU2lnblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguU2lnblByb2Nlc3NSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy9zaWduLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBzaWduUHJvY2VzczIocGFyYW1zOiBYLlNpZ25Qcm9jZXNzUXVlcnkpOiBPYnNlcnZhYmxlPFguU2lnblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguU2lnblByb2Nlc3NSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy9zaWduLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogV2F0Y2ggY29udmVyc2lvbiBzdGF0dXNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmRwb2ludCBjYWxsZWQgYnkgdGhlIGV4dGVybmFsIGNvbnZlcnNpb24gc2VydmljZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgd2F0Y2hDb252ZXJzaW9uU3RhdHVzKHdhaXRlcklkOiBhbnksIHBhcmFtczogWC5XYXRjaENvbnZlcnNpb25TdGF0dXNRdWVyeSk6IERhdGFTdGF0ZTxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5XYXRjaENvbnZlcnNpb25TdGF0dXNSZXNwb25zZT4oYC9tZWRpYWZpbGVzL2NvbnZlcnRfcHJvY2Vzc2VzLyg/UDxwcm9jZXNzX2lkPlswLTlhLXpBLVpcXF9cXC1cXD1dKykvJHt3YWl0ZXJJZH1gLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHdhdGNoQ29udmVyc2lvblN0YXR1czIod2FpdGVySWQ6IGFueSwgcGFyYW1zOiBYLldhdGNoQ29udmVyc2lvblN0YXR1c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5XYXRjaENvbnZlcnNpb25TdGF0dXNSZXNwb25zZT4oYC9tZWRpYWZpbGVzL2NvbnZlcnRfcHJvY2Vzc2VzLyg/UDxwcm9jZXNzX2lkPlswLTlhLXpBLVpcXF9cXC1cXD1dKykvJHt3YWl0ZXJJZH1gLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFF1aXp6ZXIgRW50aXRpZXMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcXVpenplci5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUXVpenplckRvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBCdWlsZCBSZWFkIFF1aXogQXR0ZW1wdHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRRdWl6YXR0ZW1wdHMocXVpeklkOiBhbnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFF1aXphdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUXVpemF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4oYC9xdWl6emVzLyR7cXVpeklkfS9hdHRlbXB0cy9gLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUXVpemF0dGVtcHRzMihxdWl6SWQ6IGFueSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFF1aXphdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUXVpemF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4oYC9xdWl6emVzLyR7cXVpeklkfS9hdHRlbXB0cy9gLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgUXVpenplc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFF1aXp6ZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRRdWl6emVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRRdWl6emVzUmVzcG9uc2VFbnRpdHlbXT4oJy9xdWl6emVzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRRdWl6emVzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRRdWl6emVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRRdWl6emVzUmVzcG9uc2VFbnRpdHlbXT4oJy9xdWl6emVzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBRdWl6XG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZVF1aXooYm9keTogWC5DcmVhdGVRdWl6Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZVF1aXpSZXNwb25zZT4oJy9xdWl6emVzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIFF1aXogQXR0ZW1wdFxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVRdWl6YXR0ZW1wdChxdWl6SWQ6IGFueSwgYm9keTogWC5DcmVhdGVRdWl6YXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUXVpemF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlUXVpemF0dGVtcHRSZXNwb25zZT4oYC9xdWl6emVzLyR7cXVpeklkfS9hdHRlbXB0cy9gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERlbGV0ZSBRdWl6XG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZVF1aXoocXVpeklkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkRlbGV0ZVF1aXpSZXNwb25zZT4oYC9xdWl6emVzLyR7cXVpeklkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBRdWl6XG4gICAgICovXG4gICAgcHVibGljIHJlYWRRdWl6KHF1aXpJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZFF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZFF1aXpSZXNwb25zZT4oYC9xdWl6emVzLyR7cXVpeklkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZFF1aXoyKHF1aXpJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRRdWl6UmVzcG9uc2U+KGAvcXVpenplcy8ke3F1aXpJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgUXVpelxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVRdWl6KHF1aXpJZDogYW55LCBib2R5OiBYLlVwZGF0ZVF1aXpCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVRdWl6UmVzcG9uc2U+KGAvcXVpenplcy8ke3F1aXpJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUmVjYWxsIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3JlY2FsbC5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUmVjYWxsRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBSZWNhbGwgU2Vzc2lvblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbmRlciBSZWNhbGwgU2Vzc2lvbiBjb21wb3NlZCBvdXQgb2YgdGhlIHNlcXVlbmNlIG9mIENhcmRzIHRoYXQgc2hvdWxkIGJlIHJlY2FsbGVkIGluIGEgZ2l2ZW4gb3JkZXIuIEJhc2VkIG9uIHRoZSBSZWNhbGxBdHRlbXB0IHN0YXRzIHJlY29tbWVuZCBhbm90aGVyIENhcmQgdG8gcmVjYWxsIGluIG9yZGVyIHRvIG1heGltaXplIHRoZSByZWNhbGwgc3BlZWQgYW5kIHN1Y2Nlc3MgcmF0ZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlUmVjYWxsU2Vzc2lvbihib2R5OiBYLkNyZWF0ZVJlY2FsbFNlc3Npb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVJlY2FsbFNlc3Npb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlUmVjYWxsU2Vzc2lvblJlc3BvbnNlPignL3JlY2FsbC9zZXNzaW9ucy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgUmVjYWxsIFN1bW1hcnlcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIHN1bW1hcnkgc3RhdHMgZm9yIGNhcmRzIGFuZCB0aGVpciByZWNhbGxfc2NvcmUgZm9yIGEgZ2l2ZW4gVXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZFJlY2FsbFN1bW1hcnkoKTogRGF0YVN0YXRlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4oJy9yZWNhbGwvc3VtbWFyeS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRSZWNhbGxTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4oJy9yZWNhbGwvc3VtbWFyeS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFN1YnNjcmlwdGlvbiBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9zdWJzY3JpcHRpb25zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBTdWJzY3JpcHRpb25zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIFJlcXVlc3QgYSBzdWJzY3JpcHRpb24gY2hhbmdlXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogV2hlbmV2ZXIgdGhlIHVzZXIgd2FudHMgdG8gY2hhbmdlIGhlciBzdWJzY3JpcHRpb24gaXQgbXVzdCBoYXBwZW4gdGhyb3VnaCB0aGlzIGVuZHBvaW50LiBJdCdzIHN0aWxsIHBvc3NpYmxlIHRoYXQgdGhlIHN1YnNjcmlwdGlvbiB3aWxsIGNoYW5nZSB3aXRob3V0IHVzZXIgYXNraW5nIGZvciBpdCwgYnV0IHRoYXQgY2FuIGhhcHBlbiB3aGVuIGRvd25ncmFkaW5nIGR1ZSB0byBtaXNzaW5nIHBheW1lbnQuXG4gICAgICovXG4gICAgcHVibGljIGNoYW5nZVN1YnNjcmlwdGlvbihib2R5OiBYLkNoYW5nZVN1YnNjcmlwdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvc3Vic2NyaXB0aW9uLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBTdWJzY3JpcHRpb24gTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvNjliYjU1YjA0NzEzODQ2ZmMzYWExYTFjMzAwYThhOWVkMjA3YjJkMy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9zdWJzY3JpcHRpb24ucHkvI2xpbmVzLTI4XG4gKi9cblxuZXhwb3J0IGVudW0gQ2hhbmdlU3Vic2NyaXB0aW9uQm9keVN1YnNjcmlwdGlvblR5cGUge1xuICAgIEZSRUUgPSAnRlJFRScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhbmdlU3Vic2NyaXB0aW9uQm9keSB7XG4gICAgc3Vic2NyaXB0aW9uX3R5cGU6IENoYW5nZVN1YnNjcmlwdGlvbkJvZHlTdWJzY3JpcHRpb25UeXBlO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy82OWJiNTViMDQ3MTM4NDZmYzNhYTFhMWMzMDBhOGE5ZWQyMDdiMmQzL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL3N1YnNjcmlwdGlvbi5weS8jbGluZXMtMzlcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENoYW5nZVN1YnNjcmlwdGlvblJlc3BvbnNlIHtcbiAgICBhdF9fcHJvY2VzczogT2JqZWN0O1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogVGFza3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vdGFza3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFRhc2tzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgVGFza3NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IHRhc2tzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkVGFza3MocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4oJy90YXNrcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFRhc2sgQmluc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgVGFza3MgQmluc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFRhc2tCaW5zKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvYmlucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrQmluczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza0JpbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvYmlucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogVGFza3MgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy81ZjIxNWZhYmJhN2ZhMzkyNTE1MWMwOThmYWQwMDUxMTYyNDUyODIxL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL3Rhc2svdmlld3MucHkvI2xpbmVzLTMzXG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRUYXNrc1F1ZXJ5UXVldWVUeXBlIHtcbiAgICBETiA9ICdETicsXG4gICAgSFAgPSAnSFAnLFxuICAgIE9UID0gJ09UJyxcbiAgICBQUiA9ICdQUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrc1F1ZXJ5IHtcbiAgICBhc2NlbmRpbmc/OiBib29sZWFuO1xuICAgIGxpbWl0PzogbnVtYmVyO1xuICAgIG9mZnNldD86IG51bWJlcjtcbiAgICBxdWV1ZV90eXBlPzogQnVsa1JlYWRUYXNrc1F1ZXJ5UXVldWVUeXBlO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjLzVmMjE1ZmFiYmE3ZmEzOTI1MTUxYzA5OGZhZDAwNTExNjI0NTI4MjEvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvdGFzay9zZXJpYWxpemVycy5weS8jbGluZXMtNTVcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZFRhc2tzUmVzcG9uc2VRdWV1ZVR5cGUge1xuICAgIEROID0gJ0ROJyxcbiAgICBIUCA9ICdIUCcsXG4gICAgT1QgPSAnT1QnLFxuICAgIFBSID0gJ1BSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHkge1xuICAgIGFyY2hpdmVkPzogYm9vbGVhbjtcbiAgICBjb250ZW50PzogT2JqZWN0O1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZG9uZV9kYXRlOiBzdHJpbmc7XG4gICAgZG9uZV90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBpZD86IG51bWJlcjtcbiAgICBvcmRlcl9udW1iZXI/OiBudW1iZXI7XG4gICAgcXVldWVfdHlwZT86IEJ1bGtSZWFkVGFza3NSZXNwb25zZVF1ZXVlVHlwZTtcbiAgICB0b3RhbF90aW1lPzogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza3NSZXNwb25zZSB7XG4gICAgdGFza3M6IEJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjLzVmMjE1ZmFiYmE3ZmEzOTI1MTUxYzA5OGZhZDAwNTExNjI0NTI4MjEvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvdGFzay92aWV3cy5weS8jbGluZXMtMzNcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZFRhc2tCaW5zUXVlcnlRdWV1ZVR5cGUge1xuICAgIEROID0gJ0ROJyxcbiAgICBIUCA9ICdIUCcsXG4gICAgT1QgPSAnT1QnLFxuICAgIFBSID0gJ1BSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tCaW5zUXVlcnkge1xuICAgIGFzY2VuZGluZz86IGJvb2xlYW47XG4gICAgbGltaXQ/OiBudW1iZXI7XG4gICAgb2Zmc2V0PzogbnVtYmVyO1xuICAgIHF1ZXVlX3R5cGU/OiBCdWxrUmVhZFRhc2tCaW5zUXVlcnlRdWV1ZVR5cGU7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvNWYyMTVmYWJiYTdmYTM5MjUxNTFjMDk4ZmFkMDA1MTE2MjQ1MjgyMS9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS90YXNrL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy03MVxuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZVF1ZXVlVHlwZSB7XG4gICAgRE4gPSAnRE4nLFxuICAgIEhQID0gJ0hQJyxcbiAgICBPVCA9ICdPVCcsXG4gICAgUFIgPSAnUFInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eSB7XG4gICAgZG9uZV9kYXRlOiBzdHJpbmc7XG4gICAgdGFza3M6IHtcbiAgICAgICAgYXJjaGl2ZWQ/OiBib29sZWFuO1xuICAgICAgICBjb250ZW50PzogT2JqZWN0O1xuICAgICAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgICAgICBkb25lX2RhdGU6IHN0cmluZztcbiAgICAgICAgZG9uZV90aW1lc3RhbXA6IG51bWJlcjtcbiAgICAgICAgaWQ/OiBudW1iZXI7XG4gICAgICAgIG9yZGVyX251bWJlcj86IG51bWJlcjtcbiAgICAgICAgcXVldWVfdHlwZT86IEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZVF1ZXVlVHlwZTtcbiAgICAgICAgdG90YWxfdGltZT86IG51bWJlcjtcbiAgICB9W107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlIHtcbiAgICB0YXNrc19iaW5zOiBCdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXTtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFdvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3dvcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBXb3Jkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFdvcmRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBXb3JkcyBieSBmaXJzdCBjaGFyYWN0ZXIuIEl0IGFsbG93cyBvbmUgdG8gZmV0Y2ggbGlzdCBvZiB3b3JkcyBieSBmaXJzdCBjaGFyYWN0ZXIuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkV29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+KCcvd29yZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZhY2FkZSBBUEkgU2VydmljZSBmb3IgYWxsIGRvbWFpbnNcbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSwgSW5qZWN0b3IgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcblxuaW1wb3J0IHsgRGF0YVN0YXRlLCBPcHRpb25zIH0gZnJvbSAnLi9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuLi9kb21haW5zL2luZGV4JztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEFQSVNlcnZpY2Uge1xuXG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBpbmplY3RvcjogSW5qZWN0b3IpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBY2NvdW50IFNldHRpbmdzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfYWNjb3VudF9zZXR0aW5nc0RvbWFpbjogWC5BY2NvdW50U2V0dGluZ3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBhY2NvdW50X3NldHRpbmdzRG9tYWluKCk6IFguQWNjb3VudFNldHRpbmdzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9hY2NvdW50X3NldHRpbmdzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hY2NvdW50X3NldHRpbmdzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5BY2NvdW50U2V0dGluZ3NEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hY2NvdW50X3NldHRpbmdzRG9tYWluO1xuICAgIH1cblxuICAgIHJlYWRBY2NvdW50c2V0dGluZygpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50X3NldHRpbmdzRG9tYWluLnJlYWRBY2NvdW50c2V0dGluZygpO1xuICAgIH1cbiAgICBcbiAgICByZWFkQWNjb3VudHNldHRpbmcyKCk6IE9ic2VydmFibGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50X3NldHRpbmdzRG9tYWluLnJlYWRBY2NvdW50c2V0dGluZzIoKTtcbiAgICB9XG5cbiAgICB1cGRhdGVBY2NvdW50c2V0dGluZyhib2R5OiBYLlVwZGF0ZUFjY291bnRzZXR0aW5nQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRfc2V0dGluZ3NEb21haW4udXBkYXRlQWNjb3VudHNldHRpbmcoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWNjb3VudHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hY2NvdW50c0RvbWFpbjogWC5BY2NvdW50c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGFjY291bnRzRG9tYWluKCk6IFguQWNjb3VudHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2FjY291bnRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hY2NvdW50c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQWNjb3VudHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hY2NvdW50c0RvbWFpbjtcbiAgICB9XG5cbiAgICBhY3RpdmF0ZUFjY291bnQoYm9keTogWC5BY3RpdmF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkFjdGl2YXRlQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLmFjdGl2YXRlQWNjb3VudChib2R5KTtcbiAgICB9XG5cbiAgICBidWxrUmVhZEFjY291bnRzKHBhcmFtczogWC5CdWxrUmVhZEFjY291bnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5idWxrUmVhZEFjY291bnRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkQWNjb3VudHMyKHBhcmFtczogWC5CdWxrUmVhZEFjY291bnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uYnVsa1JlYWRBY2NvdW50czIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBjaGFuZ2VQYXNzd29yZChib2R5OiBYLkNoYW5nZVBhc3N3b3JkQm9keSk6IE9ic2VydmFibGU8WC5DaGFuZ2VQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLmNoYW5nZVBhc3N3b3JkKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUFjY291bnQoYm9keTogWC5DcmVhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uY3JlYXRlQWNjb3VudChib2R5KTtcbiAgICB9XG5cbiAgICByZWFkQWNjb3VudCgpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnJlYWRBY2NvdW50KCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRBY2NvdW50MigpOiBPYnNlcnZhYmxlPFguUmVhZEFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5yZWFkQWNjb3VudDIoKTtcbiAgICB9XG5cbiAgICByZXNldFBhc3N3b3JkKGJvZHk6IFguUmVzZXRQYXNzd29yZEJvZHkpOiBPYnNlcnZhYmxlPFguUmVzZXRQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnJlc2V0UGFzc3dvcmQoYm9keSk7XG4gICAgfVxuXG4gICAgc2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWwoYm9keTogWC5TZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5zZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbChib2R5KTtcbiAgICB9XG5cbiAgICBzZW5kUmVzZXRQYXNzd29yZEVtYWlsKGJvZHk6IFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnNlbmRSZXNldFBhc3N3b3JkRW1haWwoYm9keSk7XG4gICAgfVxuXG4gICAgdXBkYXRlQWNjb3VudChib2R5OiBYLlVwZGF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi51cGRhdGVBY2NvdW50KGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEF0dGVtcHQgU3RhdHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hdHRlbXB0X3N0YXRzRG9tYWluOiBYLkF0dGVtcHRTdGF0c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGF0dGVtcHRfc3RhdHNEb21haW4oKTogWC5BdHRlbXB0U3RhdHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2F0dGVtcHRfc3RhdHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2F0dGVtcHRfc3RhdHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkF0dGVtcHRTdGF0c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2F0dGVtcHRfc3RhdHNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRBdHRlbXB0c3RhdHMocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRfc3RhdHNEb21haW4uYnVsa1JlYWRBdHRlbXB0c3RhdHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRBdHRlbXB0c3RhdHMyKHBhcmFtczogWC5CdWxrUmVhZEF0dGVtcHRzdGF0c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdF9zdGF0c0RvbWFpbi5idWxrUmVhZEF0dGVtcHRzdGF0czIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBjcmVhdGVBdHRlbXB0c3RhdChib2R5OiBYLkNyZWF0ZUF0dGVtcHRzdGF0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0c3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRfc3RhdHNEb21haW4uY3JlYXRlQXR0ZW1wdHN0YXQoYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdChib2R5OiBYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0X3N0YXRzRG9tYWluLmNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXQoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQXR0ZW1wdHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hdHRlbXB0c0RvbWFpbjogWC5BdHRlbXB0c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGF0dGVtcHRzRG9tYWluKCk6IFguQXR0ZW1wdHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2F0dGVtcHRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hdHRlbXB0c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQXR0ZW1wdHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hdHRlbXB0c0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEF0dGVtcHRzQnlDYXJkcyhjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0c0RvbWFpbi5idWxrUmVhZEF0dGVtcHRzQnlDYXJkcyhjYXJkSWQpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEF0dGVtcHRzQnlDYXJkczIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRzRG9tYWluLmJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzMihjYXJkSWQpO1xuICAgIH1cblxuICAgIGNyZWF0ZUF0dGVtcHQoYm9keTogWC5DcmVhdGVBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdHNEb21haW4uY3JlYXRlQXR0ZW1wdChib2R5KTtcbiAgICB9XG5cbiAgICB1cGRhdGVBdHRlbXB0KGF0dGVtcHRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0c0RvbWFpbi51cGRhdGVBdHRlbXB0KGF0dGVtcHRJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQXV0aCBUb2tlbnMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hdXRoX3Rva2Vuc0RvbWFpbjogWC5BdXRoVG9rZW5zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYXV0aF90b2tlbnNEb21haW4oKTogWC5BdXRoVG9rZW5zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9hdXRoX3Rva2Vuc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fYXV0aF90b2tlbnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkF1dGhUb2tlbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hdXRoX3Rva2Vuc0RvbWFpbjtcbiAgICB9XG5cbiAgICBhdXRob3JpemVBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLkF1dGhvcml6ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmF1dGhvcml6ZUF1dGhUb2tlbigpO1xuICAgIH1cblxuICAgIGNyZWF0ZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi5jcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZUF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4udXBkYXRlQXV0aFRva2VuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQnJpY2tzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfYnJpY2tzRG9tYWluOiBYLkJyaWNrc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGJyaWNrc0RvbWFpbigpOiBYLkJyaWNrc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fYnJpY2tzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9icmlja3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkJyaWNrc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2JyaWNrc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEdhbWVhdHRlbXB0cyhnYW1lSWQ6IGFueSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2FtZWF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4uYnVsa1JlYWRHYW1lYXR0ZW1wdHMoZ2FtZUlkKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRHYW1lYXR0ZW1wdHMyKGdhbWVJZDogYW55KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkR2FtZWF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4uYnVsa1JlYWRHYW1lYXR0ZW1wdHMyKGdhbWVJZCk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRHYW1lcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEdhbWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4uYnVsa1JlYWRHYW1lcygpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEdhbWVzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRHYW1lc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYnJpY2tzRG9tYWluLmJ1bGtSZWFkR2FtZXMyKCk7XG4gICAgfVxuXG4gICAgY3JlYXRlR2FtZShib2R5OiBYLkNyZWF0ZUdhbWVCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdhbWVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4uY3JlYXRlR2FtZShib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVHYW1lYXR0ZW1wdChnYW1lSWQ6IGFueSwgYm9keTogWC5DcmVhdGVHYW1lYXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR2FtZWF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4uY3JlYXRlR2FtZWF0dGVtcHQoZ2FtZUlkLCBib2R5KTtcbiAgICB9XG5cbiAgICBkZWxldGVHYW1lKGdhbWVJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUdhbWVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4uZGVsZXRlR2FtZShnYW1lSWQpO1xuICAgIH1cblxuICAgIHJlYWRHYW1lKGdhbWVJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEdhbWVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5icmlja3NEb21haW4ucmVhZEdhbWUoZ2FtZUlkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEdhbWUyKGdhbWVJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRHYW1lUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYnJpY2tzRG9tYWluLnJlYWRHYW1lMihnYW1lSWQpO1xuICAgIH1cblxuICAgIHVwZGF0ZUdhbWUoZ2FtZUlkOiBhbnksIGJvZHk6IFguVXBkYXRlR2FtZUJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlR2FtZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmJyaWNrc0RvbWFpbi51cGRhdGVHYW1lKGdhbWVJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FyZHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9jYXJkc0RvbWFpbjogWC5DYXJkc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGNhcmRzRG9tYWluKCk6IFguQ2FyZHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2NhcmRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9jYXJkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQ2FyZHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9jYXJkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrRGVsZXRlQ2FyZHMocGFyYW1zOiBYLkJ1bGtEZWxldGVDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtEZWxldGVDYXJkc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLmJ1bGtEZWxldGVDYXJkcyhwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkQ2FyZHMocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLmJ1bGtSZWFkQ2FyZHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRDYXJkczIocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5idWxrUmVhZENhcmRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUNhcmQoYm9keTogWC5DcmVhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4uY3JlYXRlQ2FyZChib2R5KTtcbiAgICB9XG5cbiAgICByZWFkQ2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4ucmVhZENhcmQoY2FyZElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZENhcmQyKGNhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4ucmVhZENhcmQyKGNhcmRJZCk7XG4gICAgfVxuXG4gICAgdXBkYXRlQ2FyZChjYXJkSWQ6IGFueSwgYm9keTogWC5VcGRhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4udXBkYXRlQ2FyZChjYXJkSWQsIGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENhdGVnb3JpZXMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9jYXRlZ29yaWVzRG9tYWluOiBYLkNhdGVnb3JpZXNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBjYXRlZ29yaWVzRG9tYWluKCk6IFguQ2F0ZWdvcmllc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fY2F0ZWdvcmllc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fY2F0ZWdvcmllc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQ2F0ZWdvcmllc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2NhdGVnb3JpZXNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRDYXRlZ29yaWVzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2F0ZWdvcmllc0RvbWFpbi5idWxrUmVhZENhdGVnb3JpZXMoKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRDYXRlZ29yaWVzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXRlZ29yaWVzRG9tYWluLmJ1bGtSZWFkQ2F0ZWdvcmllczIoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDb250YWN0IE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfY29udGFjdHNEb21haW46IFguQ29udGFjdHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBjb250YWN0c0RvbWFpbigpOiBYLkNvbnRhY3RzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9jb250YWN0c0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fY29udGFjdHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkNvbnRhY3RzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fY29udGFjdHNEb21haW47XG4gICAgfVxuXG4gICAgY3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHQoYm9keTogWC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jb250YWN0c0RvbWFpbi5jcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5KTtcbiAgICB9XG5cbiAgICBzZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlKGJvZHk6IFguU2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZUJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbnRhY3RzRG9tYWluLnNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2UoYm9keSk7XG4gICAgfVxuXG4gICAgdmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHQoYm9keTogWC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguVmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jb250YWN0c0RvbWFpbi52ZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEb25hdGlvbnMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9kb25hdGlvbnNEb21haW46IFguRG9uYXRpb25zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZG9uYXRpb25zRG9tYWluKCk6IFguRG9uYXRpb25zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9kb25hdGlvbnNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2RvbmF0aW9uc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRG9uYXRpb25zRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZG9uYXRpb25zRG9tYWluO1xuICAgIH1cblxuICAgIGNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb24ocGFyYW1zOiBYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25RdWVyeSk6IERhdGFTdGF0ZTxYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5kb25hdGlvbnNEb21haW4uY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbihwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBjaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uMihwYXJhbXM6IFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5KTogT2JzZXJ2YWJsZTxYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5kb25hdGlvbnNEb21haW4uY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbjIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBjcmVhdGVBbm9ueW1vdXNEb25hdGlvbihib2R5OiBYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmRvbmF0aW9uc0RvbWFpbi5jcmVhdGVBbm9ueW1vdXNEb25hdGlvbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVEb25hdGlvbihib2R5OiBYLkNyZWF0ZURvbmF0aW9uQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmRvbmF0aW9uc0RvbWFpbi5jcmVhdGVEb25hdGlvbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVEb25hdGlvbmF0dGVtcHQoYm9keTogWC5DcmVhdGVEb25hdGlvbmF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmRvbmF0aW9uc0RvbWFpbi5jcmVhdGVEb25hdGlvbmF0dGVtcHQoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRXh0ZXJuYWwgQXBwcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2V4dGVybmFsX2FwcHNEb21haW46IFguRXh0ZXJuYWxBcHBzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZXh0ZXJuYWxfYXBwc0RvbWFpbigpOiBYLkV4dGVybmFsQXBwc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZXh0ZXJuYWxfYXBwc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZXh0ZXJuYWxfYXBwc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRXh0ZXJuYWxBcHBzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZXh0ZXJuYWxfYXBwc0RvbWFpbjtcbiAgICB9XG5cbiAgICBhdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguQXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5leHRlcm5hbF9hcHBzRG9tYWluLmF1dGhvcml6ZUV4dGVybmFsQXBwQXV0aFRva2VuKCk7XG4gICAgfVxuXG4gICAgY3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5leHRlcm5hbF9hcHBzRG9tYWluLmNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRFeHRlcm5hbGFwcGNvbmYocGFyYW1zOiBYLlJlYWRFeHRlcm5hbGFwcGNvbmZRdWVyeSk6IERhdGFTdGF0ZTxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5leHRlcm5hbF9hcHBzRG9tYWluLnJlYWRFeHRlcm5hbGFwcGNvbmYocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEV4dGVybmFsYXBwY29uZjIocGFyYW1zOiBYLlJlYWRFeHRlcm5hbGFwcGNvbmZRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZXh0ZXJuYWxfYXBwc0RvbWFpbi5yZWFkRXh0ZXJuYWxhcHBjb25mMihwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEZvY3VzIFJlY29yZHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9mb2N1c19yZWNvcmRzRG9tYWluOiBYLkZvY3VzUmVjb3Jkc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGZvY3VzX3JlY29yZHNEb21haW4oKTogWC5Gb2N1c1JlY29yZHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2ZvY3VzX3JlY29yZHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ZvY3VzX3JlY29yZHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkZvY3VzUmVjb3Jkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ZvY3VzX3JlY29yZHNEb21haW47XG4gICAgfVxuXG4gICAgY3JlYXRlRm9jdXNyZWNvcmQoYm9keTogWC5DcmVhdGVGb2N1c3JlY29yZEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRm9jdXNyZWNvcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mb2N1c19yZWNvcmRzRG9tYWluLmNyZWF0ZUZvY3VzcmVjb3JkKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRGb2N1c1JlY29yZFN1bW1hcnkoKTogRGF0YVN0YXRlPFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZvY3VzX3JlY29yZHNEb21haW4ucmVhZEZvY3VzUmVjb3JkU3VtbWFyeSgpO1xuICAgIH1cbiAgICBcbiAgICByZWFkRm9jdXNSZWNvcmRTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZvY3VzX3JlY29yZHNEb21haW4ucmVhZEZvY3VzUmVjb3JkU3VtbWFyeTIoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBGcmFnbWVudCBIYXNodGFncyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ZyYWdtZW50X2hhc2h0YWdzRG9tYWluOiBYLkZyYWdtZW50SGFzaHRhZ3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBmcmFnbWVudF9oYXNodGFnc0RvbWFpbigpOiBYLkZyYWdtZW50SGFzaHRhZ3NEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2ZyYWdtZW50X2hhc2h0YWdzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9mcmFnbWVudF9oYXNodGFnc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRnJhZ21lbnRIYXNodGFnc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ZyYWdtZW50X2hhc2h0YWdzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkRnJhZ21lbnRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X2hhc2h0YWdzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRIYXNodGFncyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X2hhc2h0YWdzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF9oYXNodGFnc0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF9oYXNodGFnc0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRnJhZ21lbnQgV29yZHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9mcmFnbWVudF93b3Jkc0RvbWFpbjogWC5GcmFnbWVudFdvcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZnJhZ21lbnRfd29yZHNEb21haW4oKTogWC5GcmFnbWVudFdvcmRzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9mcmFnbWVudF93b3Jkc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZnJhZ21lbnRfd29yZHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkZyYWdtZW50V29yZHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9mcmFnbWVudF93b3Jkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEZyYWdtZW50V29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF93b3Jkc0RvbWFpbi5idWxrUmVhZEZyYWdtZW50V29yZHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRGcmFnbWVudFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF93b3Jkc0RvbWFpbi5idWxrUmVhZEZyYWdtZW50V29yZHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfd29yZHNEb21haW4uYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfd29yZHNEb21haW4uYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEZyYWdtZW50cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ZyYWdtZW50c0RvbWFpbjogWC5GcmFnbWVudHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBmcmFnbWVudHNEb21haW4oKTogWC5GcmFnbWVudHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2ZyYWdtZW50c0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZnJhZ21lbnRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5GcmFnbWVudHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9mcmFnbWVudHNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkRnJhZ21lbnRzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50cyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50czIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50czIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBjcmVhdGVGcmFnbWVudCgpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uY3JlYXRlRnJhZ21lbnQoKTtcbiAgICB9XG5cbiAgICBkZWxldGVGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uZGVsZXRlRnJhZ21lbnQoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgbWVyZ2VGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguTWVyZ2VGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5tZXJnZUZyYWdtZW50KGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIHB1Ymxpc2hGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUHVibGlzaEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnB1Ymxpc2hGcmFnbWVudChmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICByZWFkRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnJlYWRGcmFnbWVudChmcmFnbWVudElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEZyYWdtZW50MihmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnJlYWRGcmFnbWVudDIoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgcmVhZEZyYWdtZW50RGlmZihmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnJlYWRGcmFnbWVudERpZmYoZnJhZ21lbnRJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRGcmFnbWVudERpZmYyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnJlYWRGcmFnbWVudERpZmYyKGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIHJlYWRGcmFnbWVudFNhbXBsZShmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50U2FtcGxlKGZyYWdtZW50SWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkRnJhZ21lbnRTYW1wbGUyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50U2FtcGxlMihmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICB1cGRhdGVGcmFnbWVudChmcmFnbWVudElkOiBhbnksIGJvZHk6IFguVXBkYXRlRnJhZ21lbnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnVwZGF0ZUZyYWdtZW50KGZyYWdtZW50SWQsIGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEdlb21ldHJpZXMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9nZW9tZXRyaWVzRG9tYWluOiBYLkdlb21ldHJpZXNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBnZW9tZXRyaWVzRG9tYWluKCk6IFguR2VvbWV0cmllc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZ2VvbWV0cmllc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZ2VvbWV0cmllc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguR2VvbWV0cmllc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2dlb21ldHJpZXNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRHZW9tZXRyaWVzKHBhcmFtczogWC5CdWxrUmVhZEdlb21ldHJpZXNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5idWxrUmVhZEdlb21ldHJpZXMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRHZW9tZXRyaWVzMihwYXJhbXM6IFguQnVsa1JlYWRHZW9tZXRyaWVzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLmJ1bGtSZWFkR2VvbWV0cmllczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrVXBkYXRlR2VvbWV0cmllcyhib2R5OiBYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzQm9keSk6IE9ic2VydmFibGU8WC5CdWxrVXBkYXRlR2VvbWV0cmllc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4uYnVsa1VwZGF0ZUdlb21ldHJpZXMoYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZEdlb21ldHJ5QnlDYXJkKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEdlb21ldHJ5QnlDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5yZWFkR2VvbWV0cnlCeUNhcmQoY2FyZElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEdlb21ldHJ5QnlDYXJkMihjYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLnJlYWRHZW9tZXRyeUJ5Q2FyZDIoY2FyZElkKTtcbiAgICB9XG5cbiAgICByZWFkR3JhcGgocGFyYW1zOiBYLlJlYWRHcmFwaFF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEdyYXBoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5yZWFkR3JhcGgocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEdyYXBoMihwYXJhbXM6IFguUmVhZEdyYXBoUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEdyYXBoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5yZWFkR3JhcGgyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR29zc2lwIENvbW1hbmRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZ29zc2lwRG9tYWluOiBYLkdvc3NpcERvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGdvc3NpcERvbWFpbigpOiBYLkdvc3NpcERvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZ29zc2lwRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9nb3NzaXBEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkdvc3NpcERvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2dvc3NpcERvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZFNwZWVjaExhbmd1YWdlcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFNwZWVjaExhbmd1YWdlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ29zc2lwRG9tYWluLmJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkU3BlZWNoTGFuZ3VhZ2VzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRTcGVlY2hMYW5ndWFnZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdvc3NpcERvbWFpbi5idWxrUmVhZFNwZWVjaExhbmd1YWdlczIoKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFRleHRMYW5ndWFnZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRUZXh0TGFuZ3VhZ2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nb3NzaXBEb21haW4uYnVsa1JlYWRUZXh0TGFuZ3VhZ2VzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkVGV4dExhbmd1YWdlczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkVGV4dExhbmd1YWdlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ29zc2lwRG9tYWluLmJ1bGtSZWFkVGV4dExhbmd1YWdlczIoKTtcbiAgICB9XG5cbiAgICBkZXRlY3RTcGVlY2hMYW5ndWFnZXMoYm9keTogWC5EZXRlY3RTcGVlY2hMYW5ndWFnZXNCb2R5KTogT2JzZXJ2YWJsZTxYLkRldGVjdFNwZWVjaExhbmd1YWdlc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdvc3NpcERvbWFpbi5kZXRlY3RTcGVlY2hMYW5ndWFnZXMoYm9keSk7XG4gICAgfVxuXG4gICAgZGV0ZWN0VGV4dExhbmd1YWdlcyhib2R5OiBYLkRldGVjdFRleHRMYW5ndWFnZXNCb2R5KTogT2JzZXJ2YWJsZTxYLkRldGVjdFRleHRMYW5ndWFnZXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nb3NzaXBEb21haW4uZGV0ZWN0VGV4dExhbmd1YWdlcyhib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBIYXNodGFncyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2hhc2h0YWdzRG9tYWluOiBYLkhhc2h0YWdzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgaGFzaHRhZ3NEb21haW4oKTogWC5IYXNodGFnc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5faGFzaHRhZ3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2hhc2h0YWdzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5IYXNodGFnc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2hhc2h0YWdzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkSGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLmJ1bGtSZWFkSGFzaHRhZ3MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5idWxrUmVhZEhhc2h0YWdzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUhhc2h0YWcoYm9keTogWC5DcmVhdGVIYXNodGFnQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVIYXNodGFnUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4uY3JlYXRlSGFzaHRhZyhib2R5KTtcbiAgICB9XG5cbiAgICBkZWxldGVIYXNodGFnKGhhc2h0YWdJZDogYW55LCBwYXJhbXM6IFguRGVsZXRlSGFzaHRhZ1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5kZWxldGVIYXNodGFnKGhhc2h0YWdJZCwgcGFyYW1zKTtcbiAgICB9XG5cbiAgICByZWFkSGFzaHRhZ3NUb2MocGFyYW1zOiBYLlJlYWRIYXNodGFnc1RvY1F1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4ucmVhZEhhc2h0YWdzVG9jKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRIYXNodGFnc1RvYzIocGFyYW1zOiBYLlJlYWRIYXNodGFnc1RvY1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLnJlYWRIYXNodGFnc1RvYzIocGFyYW1zKTtcbiAgICB9XG5cbiAgICB1cGRhdGVIYXNodGFnKGhhc2h0YWdJZDogYW55LCBib2R5OiBYLlVwZGF0ZUhhc2h0YWdCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi51cGRhdGVIYXNodGFnKGhhc2h0YWdJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogSW52b2ljZSBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ludm9pY2VzRG9tYWluOiBYLkludm9pY2VzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgaW52b2ljZXNEb21haW4oKTogWC5JbnZvaWNlc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5faW52b2ljZXNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ludm9pY2VzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5JbnZvaWNlc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ludm9pY2VzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkSW52b2ljZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaW52b2ljZXNEb21haW4uYnVsa1JlYWRJbnZvaWNlcygpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEludm9pY2VzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaW52b2ljZXNEb21haW4uYnVsa1JlYWRJbnZvaWNlczIoKTtcbiAgICB9XG5cbiAgICBjYWxjdWxhdGVEZWJ0KCk6IERhdGFTdGF0ZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5jYWxjdWxhdGVEZWJ0KCk7XG4gICAgfVxuICAgIFxuICAgIGNhbGN1bGF0ZURlYnQyKCk6IE9ic2VydmFibGU8WC5DYWxjdWxhdGVEZWJ0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaW52b2ljZXNEb21haW4uY2FsY3VsYXRlRGVidDIoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW5rcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2xpbmtzRG9tYWluOiBYLkxpbmtzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgbGlua3NEb21haW4oKTogWC5MaW5rc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fbGlua3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2xpbmtzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5MaW5rc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2xpbmtzRG9tYWluO1xuICAgIH1cblxuICAgIGRlbGV0ZUxpbmsoZnJvbUNhcmRJZDogYW55LCB0b0NhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUxpbmtSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5saW5rc0RvbWFpbi5kZWxldGVMaW5rKGZyb21DYXJkSWQsIHRvQ2FyZElkKTtcbiAgICB9XG5cbiAgICByZWFkT3JDcmVhdGVMaW5rKGJvZHk6IFguUmVhZE9yQ3JlYXRlTGlua0JvZHkpOiBPYnNlcnZhYmxlPFguUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmxpbmtzRG9tYWluLnJlYWRPckNyZWF0ZUxpbmsoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTWVkaWFJdGVtcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX21lZGlhaXRlbXNEb21haW46IFguTWVkaWFpdGVtc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IG1lZGlhaXRlbXNEb21haW4oKTogWC5NZWRpYWl0ZW1zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9tZWRpYWl0ZW1zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9tZWRpYWl0ZW1zRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5NZWRpYWl0ZW1zRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fbWVkaWFpdGVtc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZE1lZGlhaXRlbXMocGFyYW1zOiBYLkJ1bGtSZWFkTWVkaWFpdGVtc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLmJ1bGtSZWFkTWVkaWFpdGVtcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZE1lZGlhaXRlbXMyKHBhcmFtczogWC5CdWxrUmVhZE1lZGlhaXRlbXNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4uYnVsa1JlYWRNZWRpYWl0ZW1zMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGRlbGV0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55LCBwYXJhbXM6IFguRGVsZXRlTWVkaWFpdGVtUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5kZWxldGVNZWRpYWl0ZW0obWVkaWFpdGVtSWQsIHBhcmFtcyk7XG4gICAgfVxuXG4gICAgcmVhZE1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55KTogRGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE1lZGlhaXRlbShtZWRpYWl0ZW1JZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRNZWRpYWl0ZW0yKG1lZGlhaXRlbUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE1lZGlhaXRlbTIobWVkaWFpdGVtSWQpO1xuICAgIH1cblxuICAgIHJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZCgpOiBEYXRhU3RhdGU8WC5SZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLnJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZCgpO1xuICAgIH1cbiAgICBcbiAgICByZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWQyKCk6IE9ic2VydmFibGU8WC5SZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLnJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZDIoKTtcbiAgICB9XG5cbiAgICByZWFkT3JDcmVhdGVNZWRpYWl0ZW0oYm9keTogWC5SZWFkT3JDcmVhdGVNZWRpYWl0ZW1Cb2R5KTogT2JzZXJ2YWJsZTxYLlJlYWRPckNyZWF0ZU1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE9yQ3JlYXRlTWVkaWFpdGVtKGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55LCBib2R5OiBYLlVwZGF0ZU1lZGlhaXRlbUJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi51cGRhdGVNZWRpYWl0ZW0obWVkaWFpdGVtSWQsIGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uKG1lZGlhaXRlbUlkOiBhbnksIGJvZHk6IFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi51cGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvbihtZWRpYWl0ZW1JZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTm90aWZpY2F0aW9uIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfbm90aWZpY2F0aW9uc0RvbWFpbjogWC5Ob3RpZmljYXRpb25zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgbm90aWZpY2F0aW9uc0RvbWFpbigpOiBYLk5vdGlmaWNhdGlvbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX25vdGlmaWNhdGlvbnNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX25vdGlmaWNhdGlvbnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLk5vdGlmaWNhdGlvbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9ub3RpZmljYXRpb25zRG9tYWluO1xuICAgIH1cblxuICAgIGFja25vd2xlZGdlTm90aWZpY2F0aW9uKG5vdGlmaWNhdGlvbklkOiBhbnkpOiBPYnNlcnZhYmxlPFguQWNrbm93bGVkZ2VOb3RpZmljYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5ub3RpZmljYXRpb25zRG9tYWluLmFja25vd2xlZGdlTm90aWZpY2F0aW9uKG5vdGlmaWNhdGlvbklkKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZE5vdGlmaWNhdGlvbnMocGFyYW1zOiBYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5ub3RpZmljYXRpb25zRG9tYWluLmJ1bGtSZWFkTm90aWZpY2F0aW9ucyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZE5vdGlmaWNhdGlvbnMyKHBhcmFtczogWC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm5vdGlmaWNhdGlvbnNEb21haW4uYnVsa1JlYWROb3RpZmljYXRpb25zMihwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE5vdW5zIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfbm91bnNEb21haW46IFguTm91bnNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBub3Vuc0RvbWFpbigpOiBYLk5vdW5zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9ub3Vuc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fbm91bnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLk5vdW5zRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fbm91bnNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRJY29ucyhwYXJhbXM6IFguQnVsa1JlYWRJY29uc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRJY29uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubm91bnNEb21haW4uYnVsa1JlYWRJY29ucyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEljb25zMihwYXJhbXM6IFguQnVsa1JlYWRJY29uc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSWNvbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm5vdW5zRG9tYWluLmJ1bGtSZWFkSWNvbnMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUGF0aHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9wYXRoc0RvbWFpbjogWC5QYXRoc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHBhdGhzRG9tYWluKCk6IFguUGF0aHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3BhdGhzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9wYXRoc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguUGF0aHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9wYXRoc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrRGVsZXRlUGF0aHMocGFyYW1zOiBYLkJ1bGtEZWxldGVQYXRoc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtEZWxldGVQYXRoc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLmJ1bGtEZWxldGVQYXRocyhwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUGF0aHMocGFyYW1zOiBYLkJ1bGtSZWFkUGF0aHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLmJ1bGtSZWFkUGF0aHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRQYXRoczIocGFyYW1zOiBYLkJ1bGtSZWFkUGF0aHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5idWxrUmVhZFBhdGhzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZVBhdGgoYm9keTogWC5DcmVhdGVQYXRoQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4uY3JlYXRlUGF0aChib2R5KTtcbiAgICB9XG5cbiAgICByZWFkUGF0aChwYXRoSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4ucmVhZFBhdGgocGF0aElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZFBhdGgyKHBhdGhJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4ucmVhZFBhdGgyKHBhdGhJZCk7XG4gICAgfVxuXG4gICAgdXBkYXRlUGF0aChwYXRoSWQ6IGFueSwgYm9keTogWC5VcGRhdGVQYXRoQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4udXBkYXRlUGF0aChwYXRoSWQsIGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBheW1lbnQgQ2FyZHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9wYXltZW50X2NhcmRzRG9tYWluOiBYLlBheW1lbnRDYXJkc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHBheW1lbnRfY2FyZHNEb21haW4oKTogWC5QYXltZW50Q2FyZHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3BheW1lbnRfY2FyZHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3BheW1lbnRfY2FyZHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlBheW1lbnRDYXJkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3BheW1lbnRfY2FyZHNEb21haW47XG4gICAgfVxuXG4gICAgYXNEZWZhdWx0TWFya1BheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5Bc0RlZmF1bHRNYXJrUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLmFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZChwYXltZW50Q2FyZElkKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFBheW1lbnRjYXJkcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5idWxrUmVhZFBheW1lbnRjYXJkcygpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFBheW1lbnRjYXJkczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLmJ1bGtSZWFkUGF5bWVudGNhcmRzMigpO1xuICAgIH1cblxuICAgIGNyZWF0ZVBheW1lbnRjYXJkKGJvZHk6IFguQ3JlYXRlUGF5bWVudGNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5jcmVhdGVQYXltZW50Y2FyZChib2R5KTtcbiAgICB9XG5cbiAgICBkZWxldGVQYXltZW50Y2FyZChwYXltZW50Q2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLmRlbGV0ZVBheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQpO1xuICAgIH1cblxuICAgIHBheVdpdGhEZWZhdWx0UGF5bWVudENhcmQoYm9keTogWC5QYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkQm9keSk6IE9ic2VydmFibGU8WC5QYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5wYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkKGJvZHkpO1xuICAgIH1cblxuICAgIHJlbmRlclBheW1lbnRDYXJkV2lkZ2V0KCk6IERhdGFTdGF0ZTxYLlJlbmRlclBheW1lbnRDYXJkV2lkZ2V0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5yZW5kZXJQYXltZW50Q2FyZFdpZGdldCgpO1xuICAgIH1cbiAgICBcbiAgICByZW5kZXJQYXltZW50Q2FyZFdpZGdldDIoKTogT2JzZXJ2YWJsZTxYLlJlbmRlclBheW1lbnRDYXJkV2lkZ2V0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5yZW5kZXJQYXltZW50Q2FyZFdpZGdldDIoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQYXltZW50cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3BheW1lbnRzRG9tYWluOiBYLlBheW1lbnRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcGF5bWVudHNEb21haW4oKTogWC5QYXltZW50c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcGF5bWVudHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3BheW1lbnRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5QYXltZW50c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3BheW1lbnRzRG9tYWluO1xuICAgIH1cblxuICAgIHVwZGF0ZVBheW1lbnRTdGF0dXMoYm9keTogWC5VcGRhdGVQYXltZW50U3RhdHVzQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVQYXltZW50U3RhdHVzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudHNEb21haW4udXBkYXRlUGF5bWVudFN0YXR1cyhib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQcm9jZXNzZXMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9wcm9jZXNzZXNEb21haW46IFguUHJvY2Vzc2VzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcHJvY2Vzc2VzRG9tYWluKCk6IFguUHJvY2Vzc2VzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wcm9jZXNzZXNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3Byb2Nlc3Nlc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguUHJvY2Vzc2VzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fcHJvY2Vzc2VzRG9tYWluO1xuICAgIH1cblxuICAgIGNyZWF0ZURlbGV0aW9uUHJvY2Vzcyhib2R5OiBYLkNyZWF0ZURlbGV0aW9uUHJvY2Vzc0JvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRGVsZXRpb25Qcm9jZXNzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc2VzRG9tYWluLmNyZWF0ZURlbGV0aW9uUHJvY2Vzcyhib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVEb3dubG9hZFByb2Nlc3MoYm9keTogWC5DcmVhdGVEb3dubG9hZFByb2Nlc3NCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvd25sb2FkUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi5jcmVhdGVEb3dubG9hZFByb2Nlc3MoYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlTWVkaWFMb2NrKGJvZHk6IFguQ3JlYXRlTWVkaWFMb2NrQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVNZWRpYUxvY2tSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4uY3JlYXRlTWVkaWFMb2NrKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZVVwbG9hZFByb2Nlc3MoYm9keTogWC5DcmVhdGVVcGxvYWRQcm9jZXNzQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVVcGxvYWRQcm9jZXNzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc2VzRG9tYWluLmNyZWF0ZVVwbG9hZFByb2Nlc3MoYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZEludmFyaWFudHMocGFyYW1zOiBYLlJlYWRJbnZhcmlhbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkSW52YXJpYW50c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi5yZWFkSW52YXJpYW50cyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICByZWFkSW52YXJpYW50czIocGFyYW1zOiBYLlJlYWRJbnZhcmlhbnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEludmFyaWFudHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4ucmVhZEludmFyaWFudHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgcmVhZFByb2Nlc3NTdGF0ZShwYXJhbXM6IFguUmVhZFByb2Nlc3NTdGF0ZVF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZFByb2Nlc3NTdGF0ZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi5yZWFkUHJvY2Vzc1N0YXRlKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRQcm9jZXNzU3RhdGUyKHBhcmFtczogWC5SZWFkUHJvY2Vzc1N0YXRlUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZFByb2Nlc3NTdGF0ZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnByb2Nlc3Nlc0RvbWFpbi5yZWFkUHJvY2Vzc1N0YXRlMihwYXJhbXMpO1xuICAgIH1cblxuICAgIHNpZ25Qcm9jZXNzKHBhcmFtczogWC5TaWduUHJvY2Vzc1F1ZXJ5KTogRGF0YVN0YXRlPFguU2lnblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4uc2lnblByb2Nlc3MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgc2lnblByb2Nlc3MyKHBhcmFtczogWC5TaWduUHJvY2Vzc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLlNpZ25Qcm9jZXNzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucHJvY2Vzc2VzRG9tYWluLnNpZ25Qcm9jZXNzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIHdhdGNoQ29udmVyc2lvblN0YXR1cyh3YWl0ZXJJZDogYW55LCBwYXJhbXM6IFguV2F0Y2hDb252ZXJzaW9uU3RhdHVzUXVlcnkpOiBEYXRhU3RhdGU8WC5XYXRjaENvbnZlcnNpb25TdGF0dXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4ud2F0Y2hDb252ZXJzaW9uU3RhdHVzKHdhaXRlcklkLCBwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICB3YXRjaENvbnZlcnNpb25TdGF0dXMyKHdhaXRlcklkOiBhbnksIHBhcmFtczogWC5XYXRjaENvbnZlcnNpb25TdGF0dXNRdWVyeSk6IE9ic2VydmFibGU8WC5XYXRjaENvbnZlcnNpb25TdGF0dXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wcm9jZXNzZXNEb21haW4ud2F0Y2hDb252ZXJzaW9uU3RhdHVzMih3YWl0ZXJJZCwgcGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBRdWl6emVyIEVudGl0aWVzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfcXVpenplckRvbWFpbjogWC5RdWl6emVyRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcXVpenplckRvbWFpbigpOiBYLlF1aXp6ZXJEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3F1aXp6ZXJEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3F1aXp6ZXJEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlF1aXp6ZXJEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9xdWl6emVyRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUXVpemF0dGVtcHRzKHF1aXpJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRRdWl6YXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnF1aXp6ZXJEb21haW4uYnVsa1JlYWRRdWl6YXR0ZW1wdHMocXVpeklkKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRRdWl6YXR0ZW1wdHMyKHF1aXpJZDogYW55KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUXVpemF0dGVtcHRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5xdWl6emVyRG9tYWluLmJ1bGtSZWFkUXVpemF0dGVtcHRzMihxdWl6SWQpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUXVpenplcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFF1aXp6ZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnF1aXp6ZXJEb21haW4uYnVsa1JlYWRRdWl6emVzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUXVpenplczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUXVpenplc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucXVpenplckRvbWFpbi5idWxrUmVhZFF1aXp6ZXMyKCk7XG4gICAgfVxuXG4gICAgY3JlYXRlUXVpeihib2R5OiBYLkNyZWF0ZVF1aXpCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5xdWl6emVyRG9tYWluLmNyZWF0ZVF1aXooYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlUXVpemF0dGVtcHQocXVpeklkOiBhbnksIGJvZHk6IFguQ3JlYXRlUXVpemF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVF1aXphdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucXVpenplckRvbWFpbi5jcmVhdGVRdWl6YXR0ZW1wdChxdWl6SWQsIGJvZHkpO1xuICAgIH1cblxuICAgIGRlbGV0ZVF1aXoocXVpeklkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnF1aXp6ZXJEb21haW4uZGVsZXRlUXVpeihxdWl6SWQpO1xuICAgIH1cblxuICAgIHJlYWRRdWl6KHF1aXpJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZFF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5xdWl6emVyRG9tYWluLnJlYWRRdWl6KHF1aXpJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRRdWl6MihxdWl6SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnF1aXp6ZXJEb21haW4ucmVhZFF1aXoyKHF1aXpJZCk7XG4gICAgfVxuXG4gICAgdXBkYXRlUXVpeihxdWl6SWQ6IGFueSwgYm9keTogWC5VcGRhdGVRdWl6Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucXVpenplckRvbWFpbi51cGRhdGVRdWl6KHF1aXpJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjYWxsIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfcmVjYWxsRG9tYWluOiBYLlJlY2FsbERvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHJlY2FsbERvbWFpbigpOiBYLlJlY2FsbERvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcmVjYWxsRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9yZWNhbGxEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlJlY2FsbERvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3JlY2FsbERvbWFpbjtcbiAgICB9XG5cbiAgICBjcmVhdGVSZWNhbGxTZXNzaW9uKGJvZHk6IFguQ3JlYXRlUmVjYWxsU2Vzc2lvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUmVjYWxsU2Vzc2lvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnJlY2FsbERvbWFpbi5jcmVhdGVSZWNhbGxTZXNzaW9uKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRSZWNhbGxTdW1tYXJ5KCk6IERhdGFTdGF0ZTxYLlJlYWRSZWNhbGxTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucmVjYWxsRG9tYWluLnJlYWRSZWNhbGxTdW1tYXJ5KCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRSZWNhbGxTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5yZWNhbGxEb21haW4ucmVhZFJlY2FsbFN1bW1hcnkyKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU3Vic2NyaXB0aW9uIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfc3Vic2NyaXB0aW9uc0RvbWFpbjogWC5TdWJzY3JpcHRpb25zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgc3Vic2NyaXB0aW9uc0RvbWFpbigpOiBYLlN1YnNjcmlwdGlvbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3N1YnNjcmlwdGlvbnNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3N1YnNjcmlwdGlvbnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlN1YnNjcmlwdGlvbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9zdWJzY3JpcHRpb25zRG9tYWluO1xuICAgIH1cblxuICAgIGNoYW5nZVN1YnNjcmlwdGlvbihib2R5OiBYLkNoYW5nZVN1YnNjcmlwdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuc3Vic2NyaXB0aW9uc0RvbWFpbi5jaGFuZ2VTdWJzY3JpcHRpb24oYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVGFza3MgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF90YXNrc0RvbWFpbjogWC5UYXNrc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHRhc2tzRG9tYWluKCk6IFguVGFza3NEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3Rhc2tzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl90YXNrc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguVGFza3NEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl90YXNrc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZFRhc2tzKHBhcmFtczogWC5CdWxrUmVhZFRhc2tzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy50YXNrc0RvbWFpbi5idWxrUmVhZFRhc2tzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkVGFza3MyKHBhcmFtczogWC5CdWxrUmVhZFRhc2tzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMudGFza3NEb21haW4uYnVsa1JlYWRUYXNrczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFRhc2tCaW5zKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy50YXNrc0RvbWFpbi5idWxrUmVhZFRhc2tCaW5zKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkVGFza0JpbnMyKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMudGFza3NEb21haW4uYnVsa1JlYWRUYXNrQmluczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBXb3JkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3dvcmRzRG9tYWluOiBYLldvcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgd29yZHNEb21haW4oKTogWC5Xb3Jkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fd29yZHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3dvcmRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Xb3Jkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3dvcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkV29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLndvcmRzRG9tYWluLmJ1bGtSZWFkV29yZHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy53b3Jkc0RvbWFpbi5idWxrUmVhZFdvcmRzMihwYXJhbXMpO1xuICAgIH1cblxufSIsIiAgICAgICAgICAgICAgICAvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4gICAgICAgICAgICAgICAgaW1wb3J0IHsgTmdNb2R1bGUsIE1vZHVsZVdpdGhQcm92aWRlcnMgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbiAgICAgICAgICAgICAgICBpbXBvcnQgeyBIdHRwQ2xpZW50TW9kdWxlIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuXG4gICAgICAgICAgICAgICAgLyoqIERvbWFpbnMgKi9cbiAgICAgICAgICAgICAgICBpbXBvcnQgeyBBY2NvdW50U2V0dGluZ3NEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvYWNjb3VudF9zZXR0aW5ncy9pbmRleCc7XG5pbXBvcnQgeyBBY2NvdW50c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9hY2NvdW50cy9pbmRleCc7XG5pbXBvcnQgeyBBdHRlbXB0U3RhdHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvYXR0ZW1wdF9zdGF0cy9pbmRleCc7XG5pbXBvcnQgeyBBdHRlbXB0c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9hdHRlbXB0cy9pbmRleCc7XG5pbXBvcnQgeyBBdXRoVG9rZW5zRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2F1dGhfdG9rZW5zL2luZGV4JztcbmltcG9ydCB7IEJyaWNrc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9icmlja3MvaW5kZXgnO1xuaW1wb3J0IHsgQ2FyZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvY2FyZHMvaW5kZXgnO1xuaW1wb3J0IHsgQ2F0ZWdvcmllc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9jYXRlZ29yaWVzL2luZGV4JztcbmltcG9ydCB7IENvbnRhY3RzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2NvbnRhY3RzL2luZGV4JztcbmltcG9ydCB7IERvbmF0aW9uc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9kb25hdGlvbnMvaW5kZXgnO1xuaW1wb3J0IHsgRXh0ZXJuYWxBcHBzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2V4dGVybmFsX2FwcHMvaW5kZXgnO1xuaW1wb3J0IHsgRm9jdXNSZWNvcmRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZvY3VzX3JlY29yZHMvaW5kZXgnO1xuaW1wb3J0IHsgRnJhZ21lbnRIYXNodGFnc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9mcmFnbWVudF9oYXNodGFncy9pbmRleCc7XG5pbXBvcnQgeyBGcmFnbWVudFdvcmRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZyYWdtZW50X3dvcmRzL2luZGV4JztcbmltcG9ydCB7IEZyYWdtZW50c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9mcmFnbWVudHMvaW5kZXgnO1xuaW1wb3J0IHsgR2VvbWV0cmllc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9nZW9tZXRyaWVzL2luZGV4JztcbmltcG9ydCB7IEdvc3NpcERvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9nb3NzaXAvaW5kZXgnO1xuaW1wb3J0IHsgSGFzaHRhZ3NEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvaGFzaHRhZ3MvaW5kZXgnO1xuaW1wb3J0IHsgSW52b2ljZXNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvaW52b2ljZXMvaW5kZXgnO1xuaW1wb3J0IHsgTGlua3NEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvbGlua3MvaW5kZXgnO1xuaW1wb3J0IHsgTWVkaWFpdGVtc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9tZWRpYWl0ZW1zL2luZGV4JztcbmltcG9ydCB7IE5vdGlmaWNhdGlvbnNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvbm90aWZpY2F0aW9ucy9pbmRleCc7XG5pbXBvcnQgeyBOb3Vuc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9ub3Vucy9pbmRleCc7XG5pbXBvcnQgeyBQYXRoc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9wYXRocy9pbmRleCc7XG5pbXBvcnQgeyBQYXltZW50Q2FyZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcGF5bWVudF9jYXJkcy9pbmRleCc7XG5pbXBvcnQgeyBQYXltZW50c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9wYXltZW50cy9pbmRleCc7XG5pbXBvcnQgeyBQcm9jZXNzZXNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcHJvY2Vzc2VzL2luZGV4JztcbmltcG9ydCB7IFF1aXp6ZXJEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcXVpenplci9pbmRleCc7XG5pbXBvcnQgeyBSZWNhbGxEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcmVjYWxsL2luZGV4JztcbmltcG9ydCB7IFN1YnNjcmlwdGlvbnNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvc3Vic2NyaXB0aW9ucy9pbmRleCc7XG5pbXBvcnQgeyBUYXNrc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy90YXNrcy9pbmRleCc7XG5pbXBvcnQgeyBXb3Jkc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy93b3Jkcy9pbmRleCc7XG5cbiAgICAgICAgICAgICAgICAvKiogU2VydmljZXMgKi9cbiAgICAgICAgICAgICAgICBpbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG4gICAgICAgICAgICAgICAgaW1wb3J0IHsgQVBJU2VydmljZSB9IGZyb20gJy4vc2VydmljZXMvYXBpLnNlcnZpY2UnO1xuICAgICAgICAgICAgICAgIGltcG9ydCB7IENvbmZpZyB9IGZyb20gJy4vc2VydmljZXMvY29uZmlnLnNlcnZpY2UnO1xuXG4gICAgICAgICAgICAgICAgQE5nTW9kdWxlKHtcbiAgICAgICAgICAgICAgICAgICAgaW1wb3J0czogW0h0dHBDbGllbnRNb2R1bGVdLFxuICAgICAgICAgICAgICAgICAgICBwcm92aWRlcnM6IFtcbiAgICAgICAgICAgICAgICAgICAgICAgIENsaWVudFNlcnZpY2UsXG5cbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIERvbWFpbnNcbiAgICAgICAgICAgICAgICAgICAgICAgIEFjY291bnRTZXR0aW5nc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEFjY291bnRzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgQXR0ZW1wdFN0YXRzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgQXR0ZW1wdHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBBdXRoVG9rZW5zRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgQnJpY2tzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBDYXRlZ29yaWVzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgQ29udGFjdHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBEb25hdGlvbnNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBFeHRlcm5hbEFwcHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBGb2N1c1JlY29yZHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBGcmFnbWVudEhhc2h0YWdzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgRnJhZ21lbnRXb3Jkc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEZyYWdtZW50c0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEdlb21ldHJpZXNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBHb3NzaXBEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBIYXNodGFnc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIEludm9pY2VzRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgTGlua3NEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBNZWRpYWl0ZW1zRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgTm90aWZpY2F0aW9uc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIE5vdW5zRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgUGF0aHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBQYXltZW50Q2FyZHNEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBQYXltZW50c0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIFByb2Nlc3Nlc0RvbWFpbixcbiAgICAgICAgICAgICAgICAgICAgICAgIFF1aXp6ZXJEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBSZWNhbGxEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBTdWJzY3JpcHRpb25zRG9tYWluLFxuICAgICAgICAgICAgICAgICAgICAgICAgVGFza3NEb21haW4sXG4gICAgICAgICAgICAgICAgICAgICAgICBXb3Jkc0RvbWFpbixcblxuICAgICAgICAgICAgICAgICAgICAgICAgLy8gRmFjYWRlXG4gICAgICAgICAgICAgICAgICAgICAgICBBUElTZXJ2aWNlLFxuICAgICAgICAgICAgICAgICAgICBdXG4gICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICBleHBvcnQgY2xhc3MgQ29TcGhlcmVDbGllbnRNb2R1bGUge1xuICAgICAgICAgICAgICAgICAgICBzdGF0aWMgZm9yUm9vdChjb25maWc6IENvbmZpZyk6IE1vZHVsZVdpdGhQcm92aWRlcnMge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBuZ01vZHVsZTogQ29TcGhlcmVDbGllbnRNb2R1bGUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJvdmlkZXJzOiBbXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsgcHJvdmlkZTogJ2NvbmZpZycsIHVzZVZhbHVlOiBjb25maWcgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIF1cbiAgICAgICAgICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9IiwiLyoqXG4gKiBHZW5lcmF0ZWQgYnVuZGxlIGluZGV4LiBEbyBub3QgZWRpdC5cbiAqL1xuXG5leHBvcnQgKiBmcm9tICcuL3B1YmxpY19hcGknO1xuXG5leHBvcnQge0NvbmZpZyBhcyDDicK1YX0gZnJvbSAnLi9zZXJ2aWNlcy9jb25maWcuc2VydmljZSc7Il0sIm5hbWVzIjpbInJldHJ5IiwiY2F0Y2hFcnJvciIsIl8uaGFzIiwibWFwIiwiXy5pc0VtcHR5IiwiQmVoYXZpb3JTdWJqZWN0IiwidGhyb3dFcnJvciIsIkluamVjdGFibGUiLCJJbmplY3QiLCJIdHRwQ2xpZW50IiwiZmlsdGVyIiwiQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlQXR5cGUiLCJSZWFkQWNjb3VudFJlc3BvbnNlQXR5cGUiLCJVcGRhdGVBY2NvdW50UmVzcG9uc2VBdHlwZSIsIkNyZWF0ZUdhbWVCb2R5QXVkaW9MYW5ndWFnZSIsIkNyZWF0ZUdhbWVCb2R5TGFuZ3VhZ2UiLCJVcGRhdGVHYW1lQm9keUF1ZGlvTGFuZ3VhZ2UiLCJVcGRhdGVHYW1lQm9keUxhbmd1YWdlIiwiQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VUZXh0IiwiQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5RXZlbnQiLCJDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlQ3VycmVuY3kiLCJDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGUiLCJDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlU3RhdHVzIiwiQ3JlYXRlRG9uYXRpb25SZXNwb25zZUN1cnJlbmN5IiwiQ3JlYXRlRG9uYXRpb25SZXNwb25zZVByb2R1Y3RUeXBlIiwiQ3JlYXRlRG9uYXRpb25SZXNwb25zZVN0YXR1cyIsIkNyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHlFdmVudCIsIkNyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlRXZlbnQiLCJCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VDdXJyZW5jeSIsIkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZVByb2R1Y3RUeXBlIiwiUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlS2luZCIsIkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlS2luZCIsIkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VDdXJyZW5jeSIsIkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VQcm9kdWN0VHlwZSIsIkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VTdGF0dXMiLCJDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlQ3VycmVuY3kiLCJDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlUHJvZHVjdFR5cGUiLCJDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlU3RhdHVzIiwiUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlQ3VycmVuY3kiLCJQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VQcm9kdWN0VHlwZSIsIlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVN0YXR1cyIsIkNoYW5nZVN1YnNjcmlwdGlvbkJvZHlTdWJzY3JpcHRpb25UeXBlIiwiQnVsa1JlYWRUYXNrc1F1ZXJ5UXVldWVUeXBlIiwiQnVsa1JlYWRUYXNrc1Jlc3BvbnNlUXVldWVUeXBlIiwiQnVsa1JlYWRUYXNrQmluc1F1ZXJ5UXVldWVUeXBlIiwiQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlUXVldWVUeXBlIiwiWC5BY2NvdW50U2V0dGluZ3NEb21haW4iLCJYLkFjY291bnRzRG9tYWluIiwiWC5BdHRlbXB0U3RhdHNEb21haW4iLCJYLkF0dGVtcHRzRG9tYWluIiwiWC5BdXRoVG9rZW5zRG9tYWluIiwiWC5Ccmlja3NEb21haW4iLCJYLkNhcmRzRG9tYWluIiwiWC5DYXRlZ29yaWVzRG9tYWluIiwiWC5Db250YWN0c0RvbWFpbiIsIlguRG9uYXRpb25zRG9tYWluIiwiWC5FeHRlcm5hbEFwcHNEb21haW4iLCJYLkZvY3VzUmVjb3Jkc0RvbWFpbiIsIlguRnJhZ21lbnRIYXNodGFnc0RvbWFpbiIsIlguRnJhZ21lbnRXb3Jkc0RvbWFpbiIsIlguRnJhZ21lbnRzRG9tYWluIiwiWC5HZW9tZXRyaWVzRG9tYWluIiwiWC5Hb3NzaXBEb21haW4iLCJYLkhhc2h0YWdzRG9tYWluIiwiWC5JbnZvaWNlc0RvbWFpbiIsIlguTGlua3NEb21haW4iLCJYLk1lZGlhaXRlbXNEb21haW4iLCJYLk5vdGlmaWNhdGlvbnNEb21haW4iLCJYLk5vdW5zRG9tYWluIiwiWC5QYXRoc0RvbWFpbiIsIlguUGF5bWVudENhcmRzRG9tYWluIiwiWC5QYXltZW50c0RvbWFpbiIsIlguUHJvY2Vzc2VzRG9tYWluIiwiWC5RdWl6emVyRG9tYWluIiwiWC5SZWNhbGxEb21haW4iLCJYLlN1YnNjcmlwdGlvbnNEb21haW4iLCJYLlRhc2tzRG9tYWluIiwiWC5Xb3Jkc0RvbWFpbiIsIkluamVjdG9yIiwiTmdNb2R1bGUiLCJIdHRwQ2xpZW50TW9kdWxlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O1FBbUNFLHVCQUFzQyxNQUFjLEVBQVUsSUFBZ0I7WUFBeEMsV0FBTSxHQUFOLE1BQU0sQ0FBUTtZQUFVLFNBQUksR0FBSixJQUFJLENBQVk7Ozs7WUFkOUUsVUFBSyxHQUFHLElBQUksR0FBRyxFQUFzQixDQUFDO1lBS3JCLHFCQUFnQixHQUFXLFlBQVksQ0FBQzs7Ozs7O1lBT3hDLGNBQVMsR0FBRyxJQUFJLEdBQUcsRUFBRSxHQUFHLEVBQUUsQ0FBQztZQUcxQyxJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO1lBQ25DLElBQUksQ0FBQyxTQUFTO2dCQUNaLElBQUksQ0FBQyxNQUFNLENBQUMsU0FBUyxJQUFJLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQztTQUNsRDtRQUVELDJCQUFHLEdBQUgsVUFBTyxRQUFnQixFQUFFLE9BQWlCO1lBQ3hDLElBQU0sR0FBRyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUM7WUFDbEMsSUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLGNBQWMsQ0FBQyxPQUFPLENBQUMsQ0FBQztZQUNqRCxPQUFPLElBQUksQ0FBQyxJQUFJO2lCQUNiLEdBQUcsQ0FBQyxHQUFHLEVBQUUsV0FBVyxDQUFDO2lCQUNyQixJQUFJLENBQUNB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LENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO0lBQ2IsQ0FBQyxFQWxHV0MsOEJBQXNCLEtBQXRCQSw4QkFBc0IsUUFrR2pDO0FBd0ZELElBSUEsV0FBWSwyQkFBMkI7UUFDbkMsd0NBQVMsQ0FBQTtRQUNULHdDQUFTLENBQUE7UUFDVCx3Q0FBUyxDQUFBO1FBQ1Qsd0NBQVMsQ0FBQTtRQUNULHdDQUFTLENBQUE7UUFDVCx3Q0FBUyxDQUFBO1FBQ1Qsd0NBQVMsQ0FBQTtRQUNULHdDQUFTLENBQUE7UUFDVCx3Q0FBUyxDQUFBO1FBQ1Qsd0NBQVMsQ0FBQTtRQUNULHdDQUFTLENBQUE7UUFDVCx3Q0FBUyxDQUFBO1FBQ1Qsd0NBQVMsQ0FBQTtRQUNULHdDQUFTLENBQUE7UUFDVCx3Q0FBUyxDQUFBO1FBQ1Qsd0NBQVMsQ0FBQTtRQUNULHdDQUFTLENBQUE7UUFDVCx3Q0FBUyxDQUFBO0lBQ2IsQ0FBQyxFQW5CV0MsbUNBQTJCLEtBQTNCQSxtQ0FBMkIsUUFtQnRDO0FBRUQsSUFBQSxXQUFZLHNCQUFzQjtRQUM5QixtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENBQUE7UUFDVCxtQ0FBUyxDQUFBO1FBQ1QsbUNBQVMsQ0FBQTtRQUNULG1DQUFTLENB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