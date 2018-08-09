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
            return this.client.getDataState("/recall/attempts/by_card/" + cardId, { responseMap: 'attempts', authorizationRequired: true });
        };
        AttemptsDomain.prototype.bulkReadAttemptsByCards2 = function (cardId) {
            return this.client.get("/recall/attempts/by_card/" + cardId, { responseMap: 'attempts', authorizationRequired: true });
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
            return this.client.getDataState('/cards/', { params: params, responseMap: 'cards', authorizationRequired: true });
        };
        CardsDomain.prototype.bulkReadCards2 = function (params) {
            return this.client.get('/cards/', { params: params, responseMap: 'cards', authorizationRequired: true });
        };
        CardsDomain.prototype.bulkReadGeometriesOnly2 = function (params) {
            return this.client.get('/cards/', { params: params, responseMap: 'cards', authorizationRequired: true });
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
        CardsDomain.prototype.readCard2 = function (cardId, params) {
            return this.client.get("/cards/" + cardId, { params: params, authorizationRequired: true });
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
            return this.client.getDataState('/categories/', { responseMap: 'categories', authorizationRequired: true });
        };
        CategoriesDomain.prototype.bulkReadCategories2 = function () {
            return this.client.get('/categories/', { responseMap: 'categories', authorizationRequired: true });
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
                .post('/external/auth_tokens/authorize/', {}, { authorizationRequired: false });
            // .pipe(filter(x => !_.isEmpty(x)));
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
            return this.client.getDataState('/fragments/', { params: params, responseMap: 'fragments', authorizationRequired: true });
        };
        FragmentsDomain.prototype.bulkReadFragments2 = function (params) {
            return this.client.get('/fragments/', { params: params, responseMap: 'fragments', authorizationRequired: true });
        };
        /**
         * List Published Remote Fragments
         * -------------
         *
         * List Published Remote Fragments
         */
        FragmentsDomain.prototype.bulkReadPublishedFragments = function (params) {
            return this.client.getDataState('/fragments/published/', { params: params, responseMap: 'fragments', authorizationRequired: false });
        };
        FragmentsDomain.prototype.bulkReadPublishedFragments2 = function (params) {
            return this.client.get('/fragments/published/', { params: params, responseMap: 'fragments', authorizationRequired: false });
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
            return this.client.getDataState('/grid/geometries/', { params: params, responseMap: 'geometries', authorizationRequired: true });
        };
        GeometriesDomain.prototype.bulkReadGeometries2 = function (params) {
            return this.client.get('/grid/geometries/', { params: params, responseMap: 'geometries', authorizationRequired: true });
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
            return this.client.getDataState('/hashtags/', { params: params, responseMap: 'hashtags', authorizationRequired: true });
        };
        HashtagsDomain.prototype.bulkReadHashtags2 = function (params) {
            return this.client.get('/hashtags/', { params: params, responseMap: 'hashtags', authorizationRequired: true });
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
            return this.client.getDataState('/hashtags/toc', { params: params, authorizationRequired: true });
        };
        HashtagsDomain.prototype.readHashtagsToc2 = function (params) {
            return this.client.get('/hashtags/toc', { params: params, authorizationRequired: true });
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
    var InternalDomain = (function () {
        function InternalDomain(client) {
            this.client = client;
        }
        /**
         * Clear all Entries for a given User
         * -------------
         *
         * Internal view enabling one to clean up all database entries for a specific `user_id`. It must be of the utmost importance that this endpoint would not be available on the production system.
         */
        InternalDomain.prototype.deleteEntriesForUser = function (userId) {
            return this.client
                .delete("/reset/" + userId, { authorizationRequired: true })
                .pipe(operators.filter(function (x) { return !_.isEmpty(x); }));
        };
        InternalDomain.decorators = [
            { type: i0.Injectable }
        ];
        /** @nocollapse */
        InternalDomain.ctorParameters = function () {
            return [
                { type: ClientService }
            ];
        };
        return InternalDomain;
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
        MediaitemsDomain.prototype.readMediaitemByProcessId = function (processId) {
            return this.client.getDataState("/mediaitems/by_process/" + processId, { authorizationRequired: true });
        };
        MediaitemsDomain.prototype.readMediaitemByProcessId2 = function (processId) {
            return this.client.get("/mediaitems/by_process/" + processId, { authorizationRequired: true });
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
            return this.client.getDataState('/paths/', { params: params, responseMap: 'paths', authorizationRequired: true });
        };
        PathsDomain.prototype.bulkReadPaths2 = function (params) {
            return this.client.get('/paths/', { params: params, responseMap: 'paths', authorizationRequired: true });
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
        APIService.prototype.readCard2 = function (cardId, params) {
            return this.cardsDomain.readCard2(cardId, params);
        };
        APIService.prototype.bulkReadGeometriesOnly2 = function (params) {
            return this.cardsDomain.bulkReadGeometriesOnly2(params);
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
        Object.defineProperty(APIService.prototype, "internalDomain", {
            get: function () {
                if (!this._internalDomain) {
                    this._internalDomain = this.injector.get(InternalDomain);
                }
                return this._internalDomain;
            },
            enumerable: true,
            configurable: true
        });
        APIService.prototype.deleteEntriesForUser = function (userId) {
            return this.internalDomain.deleteEntriesForUser(userId);
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
        APIService.prototype.readMediaitemByProcessId = function (processId) {
            return this.mediaitemsDomain.readMediaitemByProcessId(processId);
        };
        APIService.prototype.readMediaitemByProcessId2 = function (processId) {
            return this.mediaitemsDomain.readMediaitemByProcessId2(processId);
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
    // export function configFactory(config: Config) {
    //   return new ConfigService(config);
    // }
    var ClientModule = (function () {
        function ClientModule() {
        }
        ClientModule.forRoot = function (config) {
            return {
                ngModule: ClientModule,
                providers: [
                    // {
                    //     provide: ConfigService,
                    //     useFactory: configFactory(config)
                    // },,
                    { provide: 'config', useValue: config }
                ]
            };
        };
        ClientModule.decorators = [
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
                            HashtagsDomain,
                            InternalDomain,
                            InvoicesDomain,
                            LinksDomain,
                            MediaitemsDomain,
                            NotificationsDomain,
                            PathsDomain,
                            PaymentCardsDomain,
                            PaymentsDomain,
                            RecallDomain,
                            SubscriptionsDomain,
                            TasksDomain,
                            WordsDomain,
                            // Facade
                            APIService,
                        ]
                    },] }
        ];
        return ClientModule;
    }());

    /**
     * Generated bundle index. Do not edit.
     */

    exports.ClientModule = ClientModule;
    exports.ClientService = ClientService;
    exports.APIService = APIService;
    exports.AccountSettingsDomain = AccountSettingsDomain;
    exports.AccountsDomain = AccountsDomain;
    exports.AttemptStatsDomain = AttemptStatsDomain;
    exports.AttemptsDomain = AttemptsDomain;
    exports.AuthTokensDomain = AuthTokensDomain;
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
    exports.HashtagsDomain = HashtagsDomain;
    exports.InternalDomain = InternalDomain;
    exports.InvoicesDomain = InvoicesDomain;
    exports.LinksDomain = LinksDomain;
    exports.MediaitemsDomain = MediaitemsDomain;
    exports.NotificationsDomain = NotificationsDomain;
    exports.PathsDomain = PathsDomain;
    exports.PaymentCardsDomain = PaymentCardsDomain;
    exports.PaymentsDomain = PaymentsDomain;
    exports.RecallDomain = RecallDomain;
    exports.SubscriptionsDomain = SubscriptionsDomain;
    exports.TasksDomain = TasksDomain;
    exports.WordsDomain = WordsDomain;

    Object.defineProperty(exports, '__esModule', { value: true });

})));

//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29zcGhlcmUtY2xpZW50LnVtZC5qcy5tYXAiLCJzb3VyY2VzIjpbIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9zZXJ2aWNlcy9jbGllbnQuc2VydmljZS50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2FjY291bnRfc2V0dGluZ3MvYWNjb3VudF9zZXR0aW5ncy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hY2NvdW50cy9hY2NvdW50cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hY2NvdW50cy9hY2NvdW50cy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hdHRlbXB0X3N0YXRzL2F0dGVtcHRfc3RhdHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvYXR0ZW1wdHMvYXR0ZW1wdHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvYXV0aF90b2tlbnMvYXV0aF90b2tlbnMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvY2FyZHMvY2FyZHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvY2F0ZWdvcmllcy9jYXRlZ29yaWVzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2NhdGVnb3JpZXMvY2F0ZWdvcmllcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9jb250YWN0cy9jb250YWN0cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9kb25hdGlvbnMvZG9uYXRpb25zLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2RvbmF0aW9ucy9kb25hdGlvbnMubW9kZWxzLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZXh0ZXJuYWxfYXBwcy9leHRlcm5hbF9hcHBzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ZvY3VzX3JlY29yZHMvZm9jdXNfcmVjb3Jkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9mcmFnbWVudF9oYXNodGFncy9mcmFnbWVudF9oYXNodGFncy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9mcmFnbWVudF93b3Jkcy9mcmFnbWVudF93b3Jkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9mcmFnbWVudHMvZnJhZ21lbnRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2dlb21ldHJpZXMvZ2VvbWV0cmllcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9oYXNodGFncy9oYXNodGFncy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9pbnRlcm5hbC9pbnRlcm5hbC5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9pbnZvaWNlcy9pbnZvaWNlcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9pbnZvaWNlcy9pbnZvaWNlcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9saW5rcy9saW5rcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9saW5rcy9saW5rcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9tZWRpYWl0ZW1zL21lZGlhaXRlbXMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvbm90aWZpY2F0aW9ucy9ub3RpZmljYXRpb25zLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL25vdGlmaWNhdGlvbnMvbm90aWZpY2F0aW9ucy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9wYXRocy9wYXRocy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9wYXltZW50X2NhcmRzL3BheW1lbnRfY2FyZHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcGF5bWVudF9jYXJkcy9wYXltZW50X2NhcmRzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3BheW1lbnRzL3BheW1lbnRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3JlY2FsbC9yZWNhbGwuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvc3Vic2NyaXB0aW9ucy9zdWJzY3JpcHRpb25zLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3N1YnNjcmlwdGlvbnMvc3Vic2NyaXB0aW9ucy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy90YXNrcy90YXNrcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy90YXNrcy90YXNrcy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy93b3Jkcy93b3Jkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvc2VydmljZXMvYXBpLnNlcnZpY2UudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvY2xpZW50Lm1vZHVsZS50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9jb3NwaGVyZS1jbGllbnQudHMiXSwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgSW5qZWN0IH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQge1xuICBIdHRwQ2xpZW50LFxuICBIdHRwUGFyYW1zLFxuICBIdHRwSGVhZGVycyxcbiAgSHR0cEVycm9yUmVzcG9uc2Vcbn0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgQmVoYXZpb3JTdWJqZWN0LCBTdWJqZWN0LCBPYnNlcnZhYmxlLCB0aHJvd0Vycm9yIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgeyBjYXRjaEVycm9yLCByZXRyeSwgbWFwIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ29uZmlnIH0gZnJvbSAnLi9jb25maWcuc2VydmljZSc7XG5pbXBvcnQgeyBPcHRpb25zLCBTdGF0ZSwgRGF0YVN0YXRlLCBSZXF1ZXN0U3RhdGUgfSBmcm9tICcuL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5ASW5qZWN0YWJsZSh7XG4gIHByb3ZpZGVkSW46ICdyb290J1xufSlcbmV4cG9ydCBjbGFzcyBDbGllbnRTZXJ2aWNlIHtcbiAgLyoqXG4gICAqIFN0YXRlIGZvciBhbGwgR0VUIHBheWxvYWRzXG4gICAqL1xuICBzdGF0ZSA9IG5ldyBNYXA8c3RyaW5nLCBTdGF0ZTxhbnk+PigpO1xuXG4gIHJlYWRvbmx5IGJhc2VVcmw6IHN0cmluZztcbiAgcmVhZG9ubHkgYXV0aFRva2VuOiBzdHJpbmc7XG5cbiAgcHJpdmF0ZSByZWFkb25seSBkZWZhdWx0QXV0aFRva2VuOiBzdHJpbmcgPSAnYXV0aF90b2tlbic7XG5cbiAgLyoqXG4gICAqIENhY2hlIHRpbWUgLSBldmVyeSBHRVQgcmVxdWVzdCBpcyB0YWtlbiBvbmx5IGlmIHRoZSBsYXN0IG9uZVxuICAgKiB3YXMgaW52b2tlZCBub3QgZWFybGllciB0aGVuIGBjYWNoZVRpbWVgIG1pbnMgYWdvLlxuICAgKiBPbmx5IHN1Y2Nlc3NmdWwgcmVzcG9uc2VzIGFyZSBjYWNoZWQgKDJ4eClcbiAgICovXG4gIHByaXZhdGUgcmVhZG9ubHkgY2FjaGVUaW1lID0gMTAwMCAqIDYwICogNjA7IC8vIDYwIG1pbnNcblxuICBjb25zdHJ1Y3RvcihASW5qZWN0KCdjb25maWcnKSBwcml2YXRlIGNvbmZpZzogQ29uZmlnLCBwcml2YXRlIGh0dHA6IEh0dHBDbGllbnQpIHtcbiAgICB0aGlzLmJhc2VVcmwgPSB0aGlzLmNvbmZpZy5iYXNlVXJsO1xuICAgIHRoaXMuYXV0aFRva2VuID1cbiAgICAgIHRoaXMuY29uZmlnLmF1dGhUb2tlbiB8fCB0aGlzLmRlZmF1bHRBdXRoVG9rZW47XG4gIH1cblxuICBnZXQ8VD4oZW5kcG9pbnQ6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiBPYnNlcnZhYmxlPFQ+IHtcbiAgICBjb25zdCB1cmwgPSB0aGlzLmdldFVybChlbmRwb2ludCk7XG4gICAgY29uc3QgaHR0cE9wdGlvbnMgPSB0aGlzLmdldEh0dHBPcHRpb25zKG9wdGlvbnMpO1xuICAgIHJldHVybiB0aGlzLmh0dHBcbiAgICAgIC5nZXQodXJsLCBodHRwT3B0aW9ucylcbiAgICAgIC5waXBlKHJldHJ5KDMpLCBjYXRjaEVycm9yKHRoaXMuaGFuZGxlRXJyb3IpKSBhcyBPYnNlcnZhYmxlPFQ+O1xuICB9XG5cbiAgcG9zdDxUPihlbmRwb2ludDogc3RyaW5nLCBib2R5OiBhbnksIG9wdGlvbnM/OiBPcHRpb25zKTogT2JzZXJ2YWJsZTxUPiB7XG4gICAgY29uc3QgdXJsID0gdGhpcy5nZXRVcmwoZW5kcG9pbnQpO1xuICAgIGNvbnN0IGh0dHBPcHRpb25zID0gdGhpcy5nZXRIdHRwT3B0aW9ucyhvcHRpb25zKTtcbiAgICByZXR1cm4gdGhpcy5odHRwXG4gICAgICAucG9zdCh1cmwsIGJvZHksIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBwdXQ8VD4oZW5kcG9pbnQ6IHN0cmluZywgYm9keTogYW55LCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLnB1dCh1cmwsIGJvZHksIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBkZWxldGU8VD4oZW5kcG9pbnQ6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiBPYnNlcnZhYmxlPFQ+IHtcbiAgICBjb25zdCB1cmwgPSB0aGlzLmdldFVybChlbmRwb2ludCk7XG4gICAgY29uc3QgaHR0cE9wdGlvbnMgPSB0aGlzLmdldEh0dHBPcHRpb25zKG9wdGlvbnMpO1xuICAgIHJldHVybiB0aGlzLmh0dHBcbiAgICAgIC5kZWxldGUodXJsLCBodHRwT3B0aW9ucylcbiAgICAgIC5waXBlKHJldHJ5KDMpLCBjYXRjaEVycm9yKHRoaXMuaGFuZGxlRXJyb3IpKSBhcyBPYnNlcnZhYmxlPFQ+O1xuICB9XG5cbiAgZ2V0RGF0YVN0YXRlPFQ+KGVuZHBvaW50OiBzdHJpbmcsIG9wdGlvbnM/OiBPcHRpb25zKTogRGF0YVN0YXRlPFQ+IHtcbiAgICBjb25zdCBrZXkgPSBvcHRpb25zICYmIG9wdGlvbnMucGFyYW1zID8gYCR7ZW5kcG9pbnR9XyR7SlNPTi5zdHJpbmdpZnkob3B0aW9ucy5wYXJhbXMpfWAgOiBlbmRwb2ludDtcbiAgICB0aGlzLmluaXRTdGF0ZShrZXksIG9wdGlvbnMpO1xuXG4gICAgbGV0IGNhY2hlID0gdHJ1ZTtcbiAgICBsZXQgcGFyYW1zOiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG5cbiAgICBpZiAoXy5oYXMob3B0aW9ucywgJ2NhY2hlJykpIHtcbiAgICAgIGNhY2hlID0gb3B0aW9ucy5jYWNoZTtcbiAgICB9XG5cbiAgICBpZiAoXy5oYXMob3B0aW9ucywgJ3BhcmFtcycpKSB7XG4gICAgICBwYXJhbXMgPSBvcHRpb25zLnBhcmFtcztcbiAgICB9XG5cbiAgICAvLyBHZXQgdGhlIGVuZHBvaW50IHN0YXRlXG4gICAgY29uc3Qgc3RhdGUgPSB0aGlzLnN0YXRlLmdldChrZXkpO1xuXG4gICAgLy8gRG8gbm90IGFsbG93IGludm9rZSB0aGUgc2FtZSBHRVQgcmVxdWVzdCB3aGlsZSBvbmUgaXMgcGVuZGluZ1xuICAgIGlmIChzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyAvKiYmICFfLmlzRW1wdHkocGFyYW1zKSovKSB7XG4gICAgICByZXR1cm4gc3RhdGUuZGF0YVN0YXRlO1xuICAgIH1cblxuICAgIGNvbnN0IGN1cnJlbnRUaW1lID0gK25ldyBEYXRlKCk7XG4gICAgaWYgKFxuICAgICAgY3VycmVudFRpbWUgLSBzdGF0ZS5yZXF1ZXN0U3RhdGUuY2FjaGVkQXQgPiB0aGlzLmNhY2hlVGltZSB8fFxuICAgICAgLy8gIV8uaXNFbXB0eShwYXJhbXMpIHx8XG4gICAgICAhY2FjaGVcbiAgICApIHtcbiAgICAgIHN0YXRlLnJlcXVlc3RTdGF0ZS5wZW5kaW5nID0gdHJ1ZTtcbiAgICAgIHRoaXMuZ2V0KGVuZHBvaW50LCBvcHRpb25zKVxuICAgICAgICAucGlwZShcbiAgICAgICAgICBtYXAoZGF0YSA9PiAob3B0aW9ucy5yZXNwb25zZU1hcCA/IGRhdGFbb3B0aW9ucy5yZXNwb25zZU1hcF0gOiBkYXRhKSlcbiAgICAgICAgKVxuICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgIGRhdGEgPT4ge1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmRhdGEkLm5leHQoZGF0YSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuaXNEYXRhJC5uZXh0KCFfLmlzRW1wdHkoZGF0YSkpO1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQoZmFsc2UpO1xuICAgICAgICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLnBlbmRpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIHN0YXRlLnJlcXVlc3RTdGF0ZS5jYWNoZWRBdCA9IGN1cnJlbnRUaW1lO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIHN0YXRlLmRhdGFTdGF0ZS5pc0RhdGEkLm5leHQoZmFsc2UpO1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmRhdGEkLmVycm9yKG51bGwpO1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQoZmFsc2UpO1xuICAgICAgICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLnBlbmRpbmcgPSBmYWxzZTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0YXRlLmRhdGFTdGF0ZS5sb2FkaW5nJC5uZXh0KGZhbHNlKTtcbiAgICB9XG5cbiAgICByZXR1cm4gc3RhdGUuZGF0YVN0YXRlO1xuICB9XG5cbiAgcHJpdmF0ZSBpbml0U3RhdGUoa2V5OiBzdHJpbmcsIG9wdGlvbnM/OiBPcHRpb25zKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLnN0YXRlLmhhcyhrZXkpKSB7XG4gICAgICB0aGlzLnN0YXRlLnNldChrZXksIHtcbiAgICAgICAgZGF0YVN0YXRlOiB7XG4gICAgICAgICAgbG9hZGluZyQ6IG5ldyBCZWhhdmlvclN1YmplY3QodHJ1ZSksXG4gICAgICAgICAgaXNEYXRhJDogbmV3IEJlaGF2aW9yU3ViamVjdChmYWxzZSksXG4gICAgICAgICAgZGF0YSQ6IG5ldyBCZWhhdmlvclN1YmplY3QobnVsbClcbiAgICAgICAgfSxcbiAgICAgICAgcmVxdWVzdFN0YXRlOiB7XG4gICAgICAgICAgY2FjaGVkQXQ6IDAsXG4gICAgICAgICAgcGVuZGluZzogZmFsc2VcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuc3RhdGUuZ2V0KGtleSkuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQodHJ1ZSk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBnZXRIdHRwT3B0aW9ucyhcbiAgICBvcHRpb25zPzogT3B0aW9uc1xuICApOiB7XG4gICAgcGFyYW1zPzogSHR0cFBhcmFtcyB8IHsgW3BhcmFtOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgIGhlYWRlcnM/OiBIdHRwSGVhZGVycyB8IHsgW2hlYWRlcjogc3RyaW5nXTogc3RyaW5nIHwgc3RyaW5nW10gfTtcbiAgICByZXBvcnRQcm9ncmVzcz86IGJvb2xlYW47XG4gIH0ge1xuICAgIGNvbnN0IGF1dGhvcml6YXRpb25SZXF1aXJlZCA9IF8uaGFzKG9wdGlvbnMsICdhdXRob3JpemF0aW9uUmVxdWlyZWQnKVxuICAgICAgPyBvcHRpb25zLmF1dGhvcml6YXRpb25SZXF1aXJlZFxuICAgICAgOiB0cnVlO1xuICAgIGNvbnN0IGV0YWcgPSAob3B0aW9ucyAmJiBvcHRpb25zLmV0YWcpIHx8IHVuZGVmaW5lZDtcblxuICAgIGxldCBodHRwT3B0aW9uczoge1xuICAgICAgcGFyYW1zPzogSHR0cFBhcmFtcyB8IHsgW3BhcmFtOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgICAgaGVhZGVycz86IEh0dHBIZWFkZXJzIHwgeyBbaGVhZGVyOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgICAgcmVwb3J0UHJvZ3Jlc3M/OiBib29sZWFuO1xuICAgIH0gPSB7XG4gICAgICBoZWFkZXJzOiB0aGlzLmdldEhlYWRlcnMoYXV0aG9yaXphdGlvblJlcXVpcmVkLCBldGFnKVxuICAgIH07XG5cbiAgICBpZiAoXy5oYXMob3B0aW9ucywgJ2hlYWRlcnMnKSkge1xuICAgICAgLy8gdHNsaW50OmRpc2FibGVcbiAgICAgIGZvciAobGV0IGtleSBpbiBvcHRpb25zLmhlYWRlcnMpIHtcbiAgICAgICAgaHR0cE9wdGlvbnMuaGVhZGVyc1trZXldID0gKDxhbnk+b3B0aW9ucykuaGVhZGVyc1trZXldO1xuICAgICAgfVxuICAgICAgLy8gdHNsaW50OmVuYWJsZVxuICAgIH1cblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAncGFyYW1zJykpIHtcbiAgICAgIGh0dHBPcHRpb25zLnBhcmFtcyA9IG9wdGlvbnMucGFyYW1zO1xuICAgIH1cblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAncmVwb3J0UHJvZ3Jlc3MnKSkge1xuICAgICAgaHR0cE9wdGlvbnMucmVwb3J0UHJvZ3Jlc3MgPSBvcHRpb25zLnJlcG9ydFByb2dyZXNzO1xuICAgIH1cblxuICAgIHJldHVybiBodHRwT3B0aW9ucztcbiAgfVxuXG4gIHByaXZhdGUgZ2V0SGVhZGVycyhcbiAgICBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGJvb2xlYW4sXG4gICAgZXRhZz86IHN0cmluZ1xuICApOiB7IFtrZXk6IHN0cmluZ106IHN0cmluZyB9IHtcbiAgICBsZXQgaGVhZGVycyA9IHtcbiAgICAgICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbidcbiAgICB9O1xuXG4gICAgaWYgKGF1dGhvcml6YXRpb25SZXF1aXJlZCkge1xuICAgICAgaGVhZGVyc1snQXV0aG9yaXphdGlvbiddID0gYEJlYXJlciAke3RoaXMuZ2V0VG9rZW4oKX1gO1xuICAgIH1cblxuICAgIGlmIChldGFnKSB7XG4gICAgICBoZWFkZXJzWydFVGFnJ10gPSBldGFnO1xuICAgIH1cblxuICAgIHJldHVybiBoZWFkZXJzO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRVcmwoZW5kcG9pbnQ6IHN0cmluZyk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGAke3RoaXMuYmFzZVVybH0ke2VuZHBvaW50fWA7XG4gIH1cblxuICBwcml2YXRlIGdldFRva2VuKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGxvY2FsU3RvcmFnZS5nZXRJdGVtKHRoaXMuYXV0aFRva2VuKTtcbiAgfVxuXG4gIHByaXZhdGUgaGFuZGxlRXJyb3IoZXJyb3I6IEh0dHBFcnJvclJlc3BvbnNlKSB7XG4gICAgaWYgKGVycm9yLmVycm9yIGluc3RhbmNlb2YgRXJyb3JFdmVudCkge1xuICAgICAgLy8gQSBjbGllbnQtc2lkZSBvciBuZXR3b3JrIGVycm9yIG9jY3VycmVkLiBIYW5kbGUgaXQgYWNjb3JkaW5nbHkuXG4gICAgICBjb25zb2xlLmVycm9yKCdBbiBlcnJvciBvY2N1cnJlZDonLCBlcnJvci5lcnJvci5tZXNzYWdlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gVGhlIGJhY2tlbmQgcmV0dXJuZWQgYW4gdW5zdWNjZXNzZnVsIHJlc3BvbnNlIGNvZGUuXG4gICAgICAvLyBUaGUgcmVzcG9uc2UgYm9keSBtYXkgY29udGFpbiBjbHVlcyBhcyB0byB3aGF0IHdlbnQgd3JvbmcsXG4gICAgICBjb25zb2xlLmVycm9yKFxuICAgICAgICBgQmFja2VuZCByZXR1cm5lZCBjb2RlICR7ZXJyb3Iuc3RhdHVzfSwgYCArIGBib2R5IHdhczogJHtlcnJvci5lcnJvcn1gXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIHJldHVybiBhbiBvYnNlcnZhYmxlIHdpdGggYSB1c2VyLWZhY2luZyBlcnJvciBtZXNzYWdlXG4gICAgcmV0dXJuIHRocm93RXJyb3IoJ1NvbWV0aGluZyBiYWQgaGFwcGVuZWQ7IHBsZWFzZSB0cnkgYWdhaW4gbGF0ZXIuJyk7XG4gIH1cbn1cbiIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQWNjb3VudCBTZXR0aW5ncyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hY2NvdW50X3NldHRpbmdzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBY2NvdW50U2V0dGluZ3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBBY2NvdW50IFNldHRpbmdzXG4gICAgICovXG4gICAgcHVibGljIHJlYWRBY2NvdW50c2V0dGluZygpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEFjY291bnRzZXR0aW5nUmVzcG9uc2U+KCcvYWNjb3VudC9zZXR0aW5ncy8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRBY2NvdW50c2V0dGluZzIoKTogT2JzZXJ2YWJsZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4oJy9hY2NvdW50L3NldHRpbmdzLycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBBY2NvdW50IFNldHRpbmdzXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUFjY291bnRzZXR0aW5nKGJvZHk6IFguVXBkYXRlQWNjb3VudHNldHRpbmdCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRzZXR0aW5nUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQWNjb3VudHNldHRpbmdSZXNwb25zZT4oJy9hY2NvdW50L3NldHRpbmdzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBY2NvdW50cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hY2NvdW50cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQWNjb3VudHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQWN0aXZhdGUgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEFjdGl2YXRlIEFjY291bnQgYnkgZGVjb2RpbmcgdGhlIGBjb2RlYCB3aGljaCBjb250YWlucyB0aGUgY29uZmlybWF0aW9uIG9mZiB0aGUgaW50ZW50IGFuZCB3YXMgc2lnbmVkIGJ5IHRoZSB1c2VyIGl0c2VsZi5cbiAgICAgKi9cbiAgICBwdWJsaWMgYWN0aXZhdGVBY2NvdW50KGJvZHk6IFguQWN0aXZhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5BY3RpdmF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQWN0aXZhdGVBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY3RpdmF0ZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgTWVudG9ycycgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZSBvbmUgdG8gUmVhZCBhbGwgYXZhaWxhYmxlIE1lbnRvciBhY2NvdW50c1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEFjY291bnRzKHBhcmFtczogWC5CdWxrUmVhZEFjY291bnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5W10+KCcvYXV0aC9hY2NvdW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRBY2NvdW50czIocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5W10+KCcvYXV0aC9hY2NvdW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENoYW5nZSBQYXNzd29yZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGNoYW5nZSBvbmUncyBwYXNzd29yZCBmb3IgYW4gYXV0aGVudGljYXRlZCB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyBjaGFuZ2VQYXNzd29yZChib2R5OiBYLkNoYW5nZVBhc3N3b3JkQm9keSk6IE9ic2VydmFibGU8WC5DaGFuZ2VQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DaGFuZ2VQYXNzd29yZFJlc3BvbnNlPignL2F1dGgvY2hhbmdlX3Bhc3N3b3JkLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEFjY291bnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGVzIFVzZXIgYW5kIEFjY291bnQgaWYgcHJvdmlkZWQgZGF0YSBhcmUgdmFsaWQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFjY291bnQoYm9keTogWC5DcmVhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUFjY291bnRSZXNwb25zZT4oJy9hdXRoL2FjY291bnRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgTXkgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgbXkgQWNjb3VudCBkYXRhLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkQWNjb3VudCgpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPignL2F1dGgvYWNjb3VudHMvbWUvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkQWNjb3VudDIoKTogT2JzZXJ2YWJsZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY2NvdW50cy9tZS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZXNldCBQYXNzd29yZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIHJlc2V0IGhlciBwYXNzd29yZCBpbiBjYXNlIHRoZSBvbGQgb25lIGNhbm5vdCBiZSByZWNhbGxlZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVzZXRQYXNzd29yZChib2R5OiBYLlJlc2V0UGFzc3dvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlJlc2V0UGFzc3dvcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguUmVzZXRQYXNzd29yZFJlc3BvbnNlPignL2F1dGgvcmVzZXRfcGFzc3dvcmQvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2VuZCBBY2NvdW50IEFjdGl2YXRpb24gRW1haWxcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBTZW5kIGFuIEVtYWlsIGNvbnRhaW5pbmcgdGhlIGNvbmZpcm1hdGlvbiBsaW5rIHdoaWNoIHdoZW4gY2xpY2tlZCBraWNrcyBvZiB0aGUgQWNjb3VudCBBY3RpdmF0aW9uLiBFdmVuIHRob3VnaCB0aGUgYWN0aXZhdGlvbiBlbWFpbCBpcyBzZW5kIGF1dG9tYXRpY2FsbHkgZHVyaW5nIHRoZSBTaWduIFVwIHBoYXNlIG9uZSBzaG91bGQgaGF2ZSBhIHdheSB0byBzZW5kIGl0IGFnYWluIGluIGNhc2UgaXQgd2FzIG5vdCBkZWxpdmVyZWQuXG4gICAgICovXG4gICAgcHVibGljIHNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsKGJvZHk6IFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxCb2R5KTogT2JzZXJ2YWJsZTxYLlNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsUmVzcG9uc2U+KCcvYXV0aC9zZW5kX2FjdGl2YXRpb25fZW1haWwvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2VuZCBSZXNldCBQYXNzd29yZCBFbWFpbFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNlbmQgYW4gRW1haWwgY29udGFpbmluZyB0aGUgY29uZmlybWF0aW9uIGxpbmsgd2hpY2ggd2hlbiBjbGlja2VkIGtpY2tzIG9mIHRoZSByZWFsIFJlc2V0IFBhc3N3b3JkIG9wZXJhdGlvbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgc2VuZFJlc2V0UGFzc3dvcmRFbWFpbChib2R5OiBYLlNlbmRSZXNldFBhc3N3b3JkRW1haWxCb2R5KTogT2JzZXJ2YWJsZTxYLlNlbmRSZXNldFBhc3N3b3JkRW1haWxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbFJlc3BvbnNlPignL2F1dGgvc2VuZF9yZXNldF9wYXNzd29yZF9lbWFpbC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgTXkgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSBteSBBY2NvdW50IGRhdGEuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUFjY291bnQoYm9keTogWC5VcGRhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQWNjb3VudFJlc3BvbnNlPignL2F1dGgvYWNjb3VudHMvbWUvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEFjY291bnRzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvYWN0aXZhdGVfYWNjb3VudC5weS8jbGluZXMtOTFcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEFjdGl2YXRlQWNjb3VudEJvZHkge1xuICAgIGNvZGU6IHN0cmluZztcbiAgICBlbWFpbDogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBBY3RpdmF0ZUFjY291bnRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2FjY291bnQucHkvI2xpbmVzLTE3OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRBY2NvdW50c1F1ZXJ5IHtcbiAgICB1c2VyX2lkczogbnVtYmVyW107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvc2VyaWFsaXplcnMucHkvI2xpbmVzLTIzXG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlQXR5cGUge1xuICAgIEFETUlOID0gJ0FETUlOJyxcbiAgICBGUkVFID0gJ0ZSRUUnLFxuICAgIExFQVJORVIgPSAnTEVBUk5FUicsXG4gICAgTUVOVE9SID0gJ01FTlRPUicsXG4gICAgUEFSVE5FUiA9ICdQQVJUTkVSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHkge1xuICAgIGF0eXBlPzogQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlQXR5cGU7XG4gICAgYXZhdGFyX3VyaT86IHN0cmluZztcbiAgICBzaG93X2luX3Jhbmtpbmc/OiBib29sZWFuO1xuICAgIHVzZXJfaWQ/OiBhbnk7XG4gICAgdXNlcm5hbWU/OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlIHtcbiAgICBkYXRhOiBCdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9jaGFuZ2VfcGFzc3dvcmQucHkvI2xpbmVzLTI0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDaGFuZ2VQYXNzd29yZEJvZHkge1xuICAgIHBhc3N3b3JkOiBzdHJpbmc7XG4gICAgcGFzc3dvcmRfYWdhaW46IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhbmdlUGFzc3dvcmRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2FjY291bnQucHkvI2xpbmVzLTExNFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlQWNjb3VudEJvZHkge1xuICAgIGVtYWlsOiBzdHJpbmc7XG4gICAgcGFzc3dvcmQ6IHN0cmluZztcbiAgICBwYXNzd29yZF9hZ2Fpbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVBY2NvdW50UmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC9zZXJpYWxpemVycy5weS8jbGluZXMtOFxuICovXG5cbmV4cG9ydCBlbnVtIFJlYWRBY2NvdW50UmVzcG9uc2VBdHlwZSB7XG4gICAgQURNSU4gPSAnQURNSU4nLFxuICAgIEZSRUUgPSAnRlJFRScsXG4gICAgTEVBUk5FUiA9ICdMRUFSTkVSJyxcbiAgICBNRU5UT1IgPSAnTUVOVE9SJyxcbiAgICBQQVJUTkVSID0gJ1BBUlRORVInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFJlYWRBY2NvdW50UmVzcG9uc2Uge1xuICAgIGF0eXBlPzogUmVhZEFjY291bnRSZXNwb25zZUF0eXBlO1xuICAgIGF2YXRhcl91cmk/OiBzdHJpbmc7XG4gICAgc2hvd19pbl9yYW5raW5nPzogYm9vbGVhbjtcbiAgICB1c2VyX2lkPzogYW55O1xuICAgIHVzZXJuYW1lPzogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL3Jlc2V0X3Bhc3N3b3JkLnB5LyNsaW5lcy05NFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVzZXRQYXNzd29yZEJvZHkge1xuICAgIGNvZGU6IHN0cmluZztcbiAgICBlbWFpbDogc3RyaW5nO1xuICAgIHBhc3N3b3JkOiBzdHJpbmc7XG4gICAgcGFzc3dvcmRfYWdhaW46IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC9zZXJpYWxpemVycy5weS8jbGluZXMtMzBcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFJlc2V0UGFzc3dvcmRSZXNwb25zZSB7XG4gICAgdG9rZW46IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9hY3RpdmF0ZV9hY2NvdW50LnB5LyNsaW5lcy00NlxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxCb2R5IHtcbiAgICBlbWFpbDogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBTZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvcmVzZXRfcGFzc3dvcmQucHkvI2xpbmVzLTMxXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBTZW5kUmVzZXRQYXNzd29yZEVtYWlsQm9keSB7XG4gICAgZW1haWw6IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgU2VuZFJlc2V0UGFzc3dvcmRFbWFpbFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvYWNjb3VudC5weS8jbGluZXMtNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFVwZGF0ZUFjY291bnRCb2R5IHtcbiAgICBhdmF0YXJfdXJpPzogc3RyaW5nO1xuICAgIHNob3dfaW5fcmFua2luZz86IGJvb2xlYW47XG4gICAgdXNlcm5hbWU/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvc2VyaWFsaXplcnMucHkvI2xpbmVzLThcbiAqL1xuXG5leHBvcnQgZW51bSBVcGRhdGVBY2NvdW50UmVzcG9uc2VBdHlwZSB7XG4gICAgQURNSU4gPSAnQURNSU4nLFxuICAgIEZSRUUgPSAnRlJFRScsXG4gICAgTEVBUk5FUiA9ICdMRUFSTkVSJyxcbiAgICBNRU5UT1IgPSAnTUVOVE9SJyxcbiAgICBQQVJUTkVSID0gJ1BBUlRORVInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFVwZGF0ZUFjY291bnRSZXNwb25zZSB7XG4gICAgYXR5cGU/OiBVcGRhdGVBY2NvdW50UmVzcG9uc2VBdHlwZTtcbiAgICBhdmF0YXJfdXJpPzogc3RyaW5nO1xuICAgIHNob3dfaW5fcmFua2luZz86IGJvb2xlYW47XG4gICAgdXNlcl9pZD86IGFueTtcbiAgICB1c2VybmFtZT86IHN0cmluZztcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEF0dGVtcHQgU3RhdHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vYXR0ZW1wdF9zdGF0cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQXR0ZW1wdFN0YXRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgQXR0ZW1wdCBTdGF0c1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgQXR0ZW1wdCBTdGF0cyBieSBmaWx0ZXJpbmcgZXhpc3Rpbmcgb25lcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRBdHRlbXB0c3RhdHMocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPignL3JlY2FsbC9hdHRlbXB0X3N0YXRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEF0dGVtcHRzdGF0czIocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdF9zdGF0cy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBBdHRlbXB0IFN0YXRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgQXR0ZW1wdCBTdGF0IHdoaWNoIHN0b3JlcyBpbmZvcm1hdGlvbiBhYm91dCBiYXNpcyBzdGF0aXN0aWNzIG9mIGEgcGFydGljdWxhciByZWNhbGwgYXR0ZW1wdC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQXR0ZW1wdHN0YXQoYm9keTogWC5DcmVhdGVBdHRlbXB0c3RhdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXR0ZW1wdHN0YXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlQXR0ZW1wdHN0YXRSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdF9zdGF0cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBFeHRlcm5hbCBBdHRlbXB0IFN0YXRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgRXh0ZXJuYWwgQXR0ZW1wdCBTdGF0IG1lYW5pbmcgb25lIHdoaWNoIHdhcyByZW5kZXJlZCBlbHNld2hlcmUgaW4gYW55IG9mIHRoZSBtdWx0aXBsZSBDb1NwaGVyZSBhcHBzLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0KGJvZHk6IFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0UmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRfc3RhdHMvZXh0ZXJuYWwvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEF0dGVtcHRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2F0dGVtcHRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBdHRlbXB0c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IEF0dGVtcHRzIEJ5IENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IEF0dGVtcHRzIGZvciBhIHNwZWNpZmljIENhcmQgZ2l2ZW4gYnkgaXRzIElkLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEF0dGVtcHRzQnlDYXJkcyhjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPihgL3JlY2FsbC9hdHRlbXB0cy9ieV9jYXJkLyR7Y2FyZElkfWAsIHsgcmVzcG9uc2VNYXA6ICdhdHRlbXB0cycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzMihjYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzUmVzcG9uc2VFbnRpdHlbXT4oYC9yZWNhbGwvYXR0ZW1wdHMvYnlfY2FyZC8ke2NhcmRJZH1gLCB7IHJlc3BvbnNlTWFwOiAnYXR0ZW1wdHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEF0dGVtcHRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgQXR0ZW1wdCB3aGljaCBpcyBhIHJlZmxlY3Rpb24gb2Ygc29tZW9uZSdzIGtub3dsZWRnZSByZWdhcmRpbmcgYSBnaXZlbiBDYXJkLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBdHRlbXB0KGJvZHk6IFguQ3JlYXRlQXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBdHRlbXB0UmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIEF0dGVtcHRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgZXhpc3RpbmcgQXR0ZW1wdCB3aXRoIG5ldyBjZWxscyBhbmQgLyBvciBzdHlsZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQXR0ZW1wdChhdHRlbXB0SWQ6IGFueSwgYm9keTogWC5VcGRhdGVBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQXR0ZW1wdFJlc3BvbnNlPihgL3JlY2FsbC9hdHRlbXB0cy8ke2F0dGVtcHRJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQXV0aCBUb2tlbnMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vYXV0aF90b2tlbnMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhUb2tlbnNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQXV0aG9yaXplIGEgZ2l2ZW4gdG9rZW5cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDYW4gYmUgY2FsbGVkIGJ5IHRoZSBBUEkgR2F0ZXdheSBpbiBvcmRlciB0byBhdXRob3JpemUgZXZlcnkgcmVxdWVzdCB1c2luZyBwcm92aWRlZCB0b2tlbi5cbiAgICAgKi9cbiAgICBwdWJsaWMgYXV0aG9yaXplQXV0aFRva2VuKCk6IE9ic2VydmFibGU8WC5BdXRob3JpemVBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQXV0aG9yaXplQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9hdXRob3JpemUvJywge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNpZ24gSW5cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBWYWxpZGF0ZXMgZGF0YSBwcm92aWRlZCBvbiB0aGUgaW5wdXQgYW5kIGlmIHN1Y2Nlc3NmdWwgcmV0dXJucyBhdXRoIHRva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBGYWNlYm9vayBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2ZhY2Vib29rLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBNb2JpbGUgRmFjZWJvb2sgQXV0aCBUb2tlblxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9mYWNlYm9vay9tb2JpbGUvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEdvb2dsZSBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9nb29nbGUvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1vYmlsZSBHb29nbGUgQXV0aCBUb2tlblxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvZ29vZ2xlL21vYmlsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWZyZXNoIEpXVCB0b2tlblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNob3VsZCBiZSB1c2VkIHdoZW5ldmVyIHRva2VuIGlzIGNsb3NlIHRvIGV4cGlyeSBvciBpZiBvbmUgaXMgcmVxdWVzdGVkIHRvIHJlZnJlc2ggdGhlIHRva2VuIGJlY2F1c2UgZm9yIGV4YW1wbGUgYWNjb3VudCB0eXBlIHdhcyBjaGFuZ2VkIGFuZCBuZXcgdG9rZW4gc2hvdWxkIGJlIHJlcXVlc3RlZCB0byByZWZsZWN0IHRoYXQgY2hhbmdlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZUF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvJywge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBDYXJkcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9jYXJkcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ2FyZHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZW1vdmUgbGlzdCBvZiBDYXJkcyBzcGVjaWZpZWQgYnkgdGhlaXIgaWRzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrRGVsZXRlQ2FyZHMocGFyYW1zOiBYLkJ1bGtEZWxldGVDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtEZWxldGVDYXJkc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkJ1bGtEZWxldGVDYXJkc1Jlc3BvbnNlPignL2NhcmRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBCdWxrIFJlYWQgTXVsdGlwbGUgQ2FyZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IHN1YnNldCBvZiBDYXJkcyBkZXBlbmRpbmcgb24gdmFyaW91cyBmaWx0ZXJpbmcgZmxhZ3MuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQ2FyZHMocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXJkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdjYXJkcycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkQ2FyZHMyKHBhcmFtczogWC5CdWxrUmVhZENhcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPignL2NhcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2NhcmRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRHZW9tZXRyaWVzT25seTIocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+KCcvY2FyZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnY2FyZHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRpbmcgYSBzaW5nbGUgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGNyZWF0ZSBhIHNpbmdsZSBDYXJkIGluc3RhbmNlLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVDYXJkKGJvZHk6IFguQ3JlYXRlQ2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVDYXJkUmVzcG9uc2U+KCcvY2FyZHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIENhcmQgYnkgSWRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIENhcmQgYnkgYGlkYC5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZENhcmQoY2FyZElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkQ2FyZFJlc3BvbnNlPihgL2NhcmRzLyR7Y2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZENhcmQyKGNhcmRJZDogYW55LCBwYXJhbXM/OiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZENhcmRSZXNwb25zZT4oYC9jYXJkcy8ke2NhcmRJZH1gLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0aW5nIGEgc2luZ2xlIENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBjcmVhdGUgYSBzaW5nbGUgQ2FyZCBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQ2FyZChjYXJkSWQ6IGFueSwgYm9keTogWC5VcGRhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQ2FyZFJlc3BvbnNlPihgL2NhcmRzLyR7Y2FyZElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBDYXRlZ29yaWVzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2NhdGVnb3JpZXMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIENhdGVnb3JpZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBDYXRlZ29yaWVzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBDYXRlZ29yaWVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZENhdGVnb3JpZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXRlZ29yaWVzLycsIHsgcmVzcG9uc2VNYXA6ICdjYXRlZ29yaWVzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRDYXRlZ29yaWVzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXRlZ29yaWVzLycsIHsgcmVzcG9uc2VNYXA6ICdjYXRlZ29yaWVzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQ2F0ZWdvcmllcyBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjL2I4ZGVjM2NmMTNkMTg5NzEwOTIyMDc4N2Y5OTU1NDY1NThkZTQ3N2QvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvY2F0ZWdvcnkvc2VyaWFsaXplcnMucHkvI2xpbmVzLTI3XG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VUZXh0IHtcbiAgICBGT1JHT1RURU4gPSAnRk9SR09UVEVOJyxcbiAgICBIT1QgPSAnSE9UJyxcbiAgICBOT1RfUkVDQUxMRUQgPSAnTk9UX1JFQ0FMTEVEJyxcbiAgICBQUk9CTEVNQVRJQyA9ICdQUk9CTEVNQVRJQycsXG4gICAgUkVDRU5UTFlfQURERUQgPSAnUkVDRU5UTFlfQURERUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBjb3VudDogbnVtYmVyO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIHRleHQ6IEJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlVGV4dDtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZSB7XG4gICAgZGF0YTogQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXTtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIENvbnRhY3QgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vY29udGFjdHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIENvbnRhY3RzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBBbm9ueW1vdXMgQ29udGFjdCBBdHRlbXB0XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gc2VuZCBtZXNzYWdlcyB0byBDb1NwaGVyZSdzIHN1cHBvcnQgZXZlbiBpZiB0aGUgc2VuZGVyIGlzIG5vdCBhdXRoZW50aWNhdGVkLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLkNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPignL2NvbnRhY3RzL2Fub255bW91cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTZW5kIEF1dGhlbnRpY2F0ZWQgQ29udGFjdCBNZXNzYWdlXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2VuZCB0aGUgQ29udGFjdCBNZXNzYWdlIGltbWVkaWF0ZWx5IHNpbmNlIGl0J3MgYWxyZWFkeSBmb3IgYW4gZXhpc3RpbmcgYW5kIGF1dGhlbnRpY2F0ZWQgdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgc2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZShib2R5OiBYLlNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2VCb2R5KTogT2JzZXJ2YWJsZTxYLlNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2VSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguU2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZVJlc3BvbnNlPignL2NvbnRhY3RzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVmVyaWZ5IHRoZSBjb250YWN0IGF0dGVtcHRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBWZXJpZnkgdGhlIGNvcnJlY3RuZXNzIG9mIHByb3ZpZGVkIHZlcmlmaWNhdGlvbiBjb2RlIGFuZCBzZW5kIHRoZSBtZXNzYWdlIHRvIHRoZSBDb1NwaGVyZSdzIHN1cHBvcnQuIFRoaXMgbWVjaGFuaXNtIGlzIHVzZWQgZm9yIGFub255bW91cyB1c2VycyBvbmx5LlxuICAgICAqL1xuICAgIHB1YmxpYyB2ZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLlZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPignL2NvbnRhY3RzL2Fub255bW91cy92ZXJpZnkvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBEb25hdGlvbnMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZG9uYXRpb25zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBEb25hdGlvbnNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ2hlY2sgaWYgb25lIGNhbiBhdHRlbXB0IGEgcmVxdWVzdCBkaXNwbGF5aW5nIGRvbmF0aW9uXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2luY2Ugd2UgZG9uJ3Qgd2FudCB0byBvdmVyZmxvdyB1c2VyIHdpdGggdW5uZWNlc3NhcnkgcmVxdWVzdHMgZm9yIGhpbSBkb25hdGluZyB3ZSBkbyBpdCBpbiBhIHNtYXJ0ZXIgd2F5IHVzaW5nIHNldCBvZiBoZXVyaXN0aWNzIHRoYXQgdG9nZXRoZXIgaGVscCB1cyB0byBhbnN3ZXIgdGhlIGZvbGxvd2luZyBxdWVzdGlvbjogXCJJcyBpdCB0aGUgYmVzdCBtb21lbnQgdG8gYXNrIGZvciB0aGUgZG9uYXRpb24/XCIuIEN1cnJlbnRseSB3ZSB1c2UgdGhlIGZvbGxvd2luZyBoZXVyaXN0aWNzOiAtIGlzIGFjY291bnQgb2xkIGVub3VnaD8gLSB3aGV0aGVyIHVzZXIgcmVjZW50bHkgZG9uYXRlZCAtIHdoZXRoZXIgd2UgYXR0ZW1wdGVkIHJlY2VudGx5IHRvIHJlcXVlc3QgZG9uYXRpb24gZnJvbSB0aGUgdXNlciAtIGlmIHRoZSB1c2VyIGluIGEgZ29vZCBtb29kIChhZnRlciBkb2luZyBzb21lIHN1Y2Nlc3NmdWwgcmVjYWxscylcbiAgICAgKi9cbiAgICBwdWJsaWMgY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbihwYXJhbXM6IFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5KTogRGF0YVN0YXRlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL2Nhbl9hdHRlbXB0LycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBjaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uMihwYXJhbXM6IFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5KTogT2JzZXJ2YWJsZTxYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPignL3BheW1lbnRzL2RvbmF0aW9ucy9jYW5fYXR0ZW1wdC8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZ2lzdGVyIGFub255bW91cyBkb25hdGlvblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIE9uZSBjYW4gcGVyZm9ybSBhIGRvbmF0aW9uIHBheW1lbnQgZXZlbiBpZiBub3QgYmVpbmcgYW4gYXV0aGVudGljYXRlZCB1c2VyLiBFdmVuIGluIHRoYXQgY2FzZSB3ZSBjYW5ub3QgYWxsb3cgZnVsbCBhbm9ueW1pdHkgYW5kIHdlIG11c3QgcmVxdWlyZSBhdCBsZWFzdCBlbWFpbCBhZGRyZXNzIHRvIHNlbmQgaW5mb3JtYXRpb24gcmVnYXJkaW5nIHRoZSBzdGF0dXMgb2YgdGhlIHBheW1lbnQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFub255bW91c0RvbmF0aW9uKGJvZHk6IFguQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL3JlZ2lzdGVyX2Fub255bW91cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWdpc3RlciBkb25hdGlvbiBmcm9tIGF1dGhlbnRpY2F0ZWQgdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIE9uZSBjYW4gcGVyZm9ybSBhIGRvbmF0aW9uIHBheW1lbnQgZXZlbiBhcyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZURvbmF0aW9uKGJvZHk6IFguQ3JlYXRlRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZURvbmF0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL3JlZ2lzdGVyLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGRvbmF0aW9uIGF0dGVtcHQgZm9yIGF1dGhlbnRpY2F0ZWQgdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVhY2ggRG9uYXRpb24gQXR0ZW1wdCBzaG91bGQgYmUgZm9sbG93ZWQgYnkgY3JlYXRpb24gb2YgRG9uYXRpb24gQXR0ZW1wdCBtb2RlbCBpbnN0YW5jZSB0byByZWZsZWN0IHRoYXQgZmFjdC4gSXQgYWxsb3dzIG9uZSB0byB0cmFjayBob3cgbWFueSB0aW1lcyB3ZSBhc2tlZCBhIGNlcnRhaW4gdXNlciBhYm91dCB0aGUgZG9uYXRpb24gaW4gb3JkZXIgbm90IHRvIG92ZXJmbG93IHRoYXQgdXNlciB3aXRoIHRoZW0gYW5kIG5vdCB0byBiZSB0b28gYWdncmVzc2l2ZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRG9uYXRpb25hdHRlbXB0KGJvZHk6IFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL2F0dGVtcHRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBEb25hdGlvbnMgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9kb25hdGlvbi5weS8jbGluZXMtMzBcbiAqL1xuXG5leHBvcnQgZW51bSBDaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnlFdmVudCB7XG4gICAgQ0xPU0UgPSAnQ0xPU0UnLFxuICAgIFJFQ0FMTCA9ICdSRUNBTEwnLFxuICAgIFNUQVJUID0gJ1NUQVJUJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnkge1xuICAgIGV2ZW50OiBDaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnlFdmVudDtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9kb25hdGlvbi5weS8jbGluZXMtMzRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZSB7XG4gICAgY2FuX2F0dGVtcHQ6IGJvb2xlYW47XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvZG9uYXRpb24ucHkvI2xpbmVzLTE4NFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25Cb2R5IHtcbiAgICBhbW91bnQ6IG51bWJlcjtcbiAgICBlbWFpbDogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnQucHkvI2xpbmVzLTlcbiAqL1xuXG5leHBvcnQgZW51bSBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlQ3VycmVuY3kge1xuICAgIFBMTiA9ICdQTE4nLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZVN0YXR1cyB7XG4gICAgQ0FOQ0VMRUQgPSAnQ0FOQ0VMRUQnLFxuICAgIENPTVBMRVRFRCA9ICdDT01QTEVURUQnLFxuICAgIE5FVyA9ICdORVcnLFxuICAgIFBFTkRJTkcgPSAnUEVORElORycsXG4gICAgUkVKRUNURUQgPSAnUkVKRUNURUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2Uge1xuICAgIGFtb3VudDogc3RyaW5nO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICBwcm9kdWN0OiB7XG4gICAgICAgIGN1cnJlbmN5PzogQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3RfdHlwZTogQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgIH07XG4gICAgc3RhdHVzPzogQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZVN0YXR1cztcbiAgICBzdGF0dXNfbGVkZ2VyPzogT2JqZWN0O1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL2RvbmF0aW9uLnB5LyNsaW5lcy0xODRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZURvbmF0aW9uQm9keSB7XG4gICAgYW1vdW50OiBudW1iZXI7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvcGF5bWVudC5weS8jbGluZXMtOVxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVEb25hdGlvblJlc3BvbnNlU3RhdHVzIHtcbiAgICBDQU5DRUxFRCA9ICdDQU5DRUxFRCcsXG4gICAgQ09NUExFVEVEID0gJ0NPTVBMRVRFRCcsXG4gICAgTkVXID0gJ05FVycsXG4gICAgUEVORElORyA9ICdQRU5ESU5HJyxcbiAgICBSRUpFQ1RFRCA9ICdSRUpFQ1RFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlRG9uYXRpb25SZXNwb25zZSB7XG4gICAgYW1vdW50OiBzdHJpbmc7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgY3VycmVuY3k/OiBDcmVhdGVEb25hdGlvblJlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgcHJvZHVjdF90eXBlOiBDcmVhdGVEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgfTtcbiAgICBzdGF0dXM/OiBDcmVhdGVEb25hdGlvblJlc3BvbnNlU3RhdHVzO1xuICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvZG9uYXRpb24ucHkvI2xpbmVzLTE4NFxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHlFdmVudCB7XG4gICAgQ0xPU0UgPSAnQ0xPU0UnLFxuICAgIFJFQ0FMTCA9ICdSRUNBTEwnLFxuICAgIFNUQVJUID0gJ1NUQVJUJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVEb25hdGlvbmF0dGVtcHRCb2R5IHtcbiAgICBldmVudDogQ3JlYXRlRG9uYXRpb25hdHRlbXB0Qm9keUV2ZW50O1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL2RvbmF0aW9uLnB5LyNsaW5lcy04XG4gKi9cblxuZXhwb3J0IGVudW0gQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2VFdmVudCB7XG4gICAgQ0xPU0UgPSAnQ0xPU0UnLFxuICAgIFJFQ0FMTCA9ICdSRUNBTEwnLFxuICAgIFNUQVJUID0gJ1NUQVJUJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZSB7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBldmVudDogQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2VFdmVudDtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEV4dGVybmFsIEFwcHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZXh0ZXJuYWxfYXBwcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRXh0ZXJuYWxBcHBzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIEF1dGhvcml6ZSBhIGdpdmVuIGV4dGVybmFsIGFwcCB0b2tlblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENhbiBiZSBjYWxsZWQgYnkgdGhlIEFQSSBHYXRld2F5IGluIG9yZGVyIHRvIGF1dGhvcml6ZSBldmVyeSByZXF1ZXN0IHVzaW5nIHByb3ZpZGVkIHRva2VuLiBJdCBtdXN0IGJlIHVzZWQgb25seSBmb3IgZXh0ZXJuYWwgYXBwIHRva2Vucywgd2hpY2ggYXJlIHVzZWQgYnkgdGhlIGV4dGVybmFsIGFwcHMgdG8gbWFrZSBjYWxscyBvbiBiZWhhbGYgb2YgYSBnaXZlbiB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyBhdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguQXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4oJy9leHRlcm5hbC9hdXRoX3Rva2Vucy9hdXRob3JpemUvJywge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLy8gLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRXh0ZXJuYWwgQXBwIENvbmZpZ3VyYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW5SZXNwb25zZT4oJy9leHRlcm5hbC9hdXRoX3Rva2Vucy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRXh0ZXJuYWwgQXBwIGNvbmZpZ3VyYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEV4dGVybmFsYXBwY29uZihwYXJhbXM6IFguUmVhZEV4dGVybmFsYXBwY29uZlF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+KCcvZXh0ZXJuYWwvYXBwcy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEV4dGVybmFsYXBwY29uZjIocGFyYW1zOiBYLlJlYWRFeHRlcm5hbGFwcGNvbmZRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4oJy9leHRlcm5hbC9hcHBzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBGb2N1cyBSZWNvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZvY3VzX3JlY29yZHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZvY3VzUmVjb3Jkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgRm9jdXMgUmVjb3JkXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZvY3VzcmVjb3JkKGJvZHk6IFguQ3JlYXRlRm9jdXNyZWNvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZvY3VzcmVjb3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZvY3VzcmVjb3JkUmVzcG9uc2U+KCcvZm9jdXNfcmVjb3Jkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRm9jdXMgUmVjb3JkIFN1bW1hcnlcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZvY3VzUmVjb3JkU3VtbWFyeSgpOiBEYXRhU3RhdGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4oJy9mb2N1c19yZWNvcmRzL3N1bW1hcnkvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRm9jdXNSZWNvcmRTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+KCcvZm9jdXNfcmVjb3Jkcy9zdW1tYXJ5LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRnJhZ21lbnQgSGFzaHRhZ3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZnJhZ21lbnRfaGFzaHRhZ3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZyYWdtZW50SGFzaHRhZ3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBIYXNodGFnc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgSGFzaHRhZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL2hhc2h0YWdzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy9oYXNodGFncy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgUHVibGlzaGVkIEhhc2h0YWdzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgSGFzaHRhZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL2hhc2h0YWdzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL2hhc2h0YWdzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZyYWdtZW50IFdvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZyYWdtZW50X3dvcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBGcmFnbWVudFdvcmRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgV29yZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFdvcmRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvd29yZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBXb3Jkc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFdvcmRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBGcmFnbWVudHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZnJhZ21lbnRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBGcmFnbWVudHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBSZW1vdGUgRnJhZ21lbnRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBSZW1vdGUgRnJhZ21lbnRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2ZyYWdtZW50cycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZnJhZ21lbnRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBSZW1vdGUgRnJhZ21lbnRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdmcmFnbWVudHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZnJhZ21lbnRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQ3JlYXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVGcmFnbWVudCgpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRnJhZ21lbnRSZXNwb25zZT4oJy9mcmFnbWVudHMvJywge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRGVsZXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIERlbGV0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTWVyZ2UgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTWVyZ2UgUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIG1lcmdlRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLk1lcmdlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguTWVyZ2VGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L21lcmdlL2AsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFB1Ymxpc2ggUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUHVibGlzaCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgcHVibGlzaEZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5QdWJsaXNoRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5QdWJsaXNoRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9wdWJsaXNoL2AsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50MihmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBGcmFnbWVudCBEaWZmXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBGcmFnbWVudCBEaWZmXG4gICAgICovXG4gICAgcHVibGljIHJlYWRGcmFnbWVudERpZmYoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vZGlmZi9gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRGcmFnbWVudERpZmYyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9kaWZmL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRnJhZ21lbnQgU2FtcGxlXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBGcmFnbWVudCBTYW1wbGVcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50U2FtcGxlKGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9zYW1wbGUvYCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50U2FtcGxlMihmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L3NhbXBsZS9gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUZyYWdtZW50Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZUZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogR2VvbWV0cmllcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9nZW9tZXRyaWVzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBHZW9tZXRyaWVzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgR2VvbWV0cmllc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgR2VvbWV0cmllcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRHZW9tZXRyaWVzKHBhcmFtczogWC5CdWxrUmVhZEdlb21ldHJpZXNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+KCcvZ3JpZC9nZW9tZXRyaWVzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2dlb21ldHJpZXMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEdlb21ldHJpZXMyKHBhcmFtczogWC5CdWxrUmVhZEdlb21ldHJpZXNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEdlb21ldHJpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEdlb21ldHJpZXNSZXNwb25zZUVudGl0eVtdPignL2dyaWQvZ2VvbWV0cmllcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdnZW9tZXRyaWVzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgVXBkYXRlIEdlb21ldHJpZXNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgaW4gYSBCdWxrIGxpc3Qgb2YgR2VvbWV0cmllcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1VwZGF0ZUdlb21ldHJpZXMoYm9keTogWC5CdWxrVXBkYXRlR2VvbWV0cmllc0JvZHkpOiBPYnNlcnZhYmxlPFguQnVsa1VwZGF0ZUdlb21ldHJpZXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5CdWxrVXBkYXRlR2VvbWV0cmllc1Jlc3BvbnNlPignL2dyaWQvZ2VvbWV0cmllcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgR2VvbWV0cnkgYnkgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgYSBHZW9tZXRyeSBlbnRpdHkgZ2l2ZW4gdGhlIGlkIG9mIENhcmQgd2hpY2ggaXMgdGhlIHBhcmVudCBvZiB0aGUgR2VvbWV0cnkgZW50aXR5LlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkR2VvbWV0cnlCeUNhcmQoY2FyZElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEdlb21ldHJ5QnlDYXJkUmVzcG9uc2U+KGAvZ3JpZC9nZW9tZXRyaWVzL2J5X2NhcmQvJHtjYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkR2VvbWV0cnlCeUNhcmQyKGNhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4oYC9ncmlkL2dlb21ldHJpZXMvYnlfY2FyZC8ke2NhcmRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEdyYXBoXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVuZGVyIGFuZCByZWFkIEdyYXBoIG1hZGUgb3V0IG9mIGFsbCBDYXJkcyBhbmQgTGlua3MgYmVsb25naW5nIHRvIGEgZ2l2ZW4gdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEdyYXBoKHBhcmFtczogWC5SZWFkR3JhcGhRdWVyeSk6IERhdGFTdGF0ZTxYLlJlYWRHcmFwaFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkR3JhcGhSZXNwb25zZT4oJy9ncmlkL2dyYXBocy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEdyYXBoMihwYXJhbXM6IFguUmVhZEdyYXBoUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEdyYXBoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRHcmFwaFJlc3BvbnNlPignL2dyaWQvZ3JhcGhzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBIYXNodGFncyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9oYXNodGFncy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSGFzaHRhZ3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBIYXNodGFnc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGxpc3QgYSBzZXJpZXMgb2YgSGFzaHRhZyBpbnN0YW5jZXMuIEl0IGFjY2VwdHMgdmFyaW91cyBxdWVyeSBwYXJhbWV0ZXJzIHN1Y2ggYXM6IC0gYGxpbWl0YCAtIGBvZmZzZXRgIC0gYGZpcnN0X2NoYXJhY3RlcmBcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2hhc2h0YWdzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2hhc2h0YWdzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvaGFzaHRhZ3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnaGFzaHRhZ3MnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRpbmcgYSBzaW5nbGUgSGFzaHRhZ1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGNyZWF0ZSBhIHNpbmdsZSBIYXNodGFnIGluc3RhbmNlLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVIYXNodGFnKGJvZHk6IFguQ3JlYXRlSGFzaHRhZ0JvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVIYXNodGFnUmVzcG9uc2U+KCcvaGFzaHRhZ3MvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmluZyBhIHNpbmdsZSBIYXNodGFnXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gZGV0YWNoIGEgc2luZ2xlIEhhc2h0YWcgaW5zdGFuY2UgZnJvbSBhIGxpc3QgY2FyZHMgZ2l2ZW4gYnkgYGNhcmRfaWRzYC5cbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlSGFzaHRhZyhoYXNodGFnSWQ6IGFueSwgcGFyYW1zOiBYLkRlbGV0ZUhhc2h0YWdRdWVyeSk6IE9ic2VydmFibGU8WC5EZWxldGVIYXNodGFnUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlSGFzaHRhZ1Jlc3BvbnNlPihgL2hhc2h0YWdzLyR7aGFzaHRhZ0lkfWAsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IEhhc2h0YWdzIFRPQ1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGxpc3QgSGFzaHRhZ3MgVGFibGUgb2YgQ29udGVudHMgbWFkZSBvdXQgb2YgSGFzaHRhZ3MuIE5vdGU6IEN1cnJlbnRseSB0aGlzIGVuZHBvaW50IHJldHVybnMgb25seSBhIGZsYXQgbGlzdCBvZiBoYXNodGFncyB3aXRoIHRoZSBjb3VudCBvZiBDYXJkcyB3aXRoIHdoaWNoIHRoZXkncmUgYXR0YWNoZWQgdG8uIEluIHRoZSBmdXR1cmUgdGhvdWdoIG9uZSBjb3VsZCBwcm9wb3NlIGEgbWVjaGFuaXNtIHdoaWNoIGNvdWxkIGNhbGN1bGF0ZSBoaWVyYXJjaHkgYmV0d2VlbiB0aG9zZSBoYXNodGFncyAocGFyZW50IC0gY2hpbGQgcmVsYXRpb25zaGlwcykgYW5kIG9yZGVyaW5nIGJhc2VkIG9uIHRoZSBrbm93bGVkZ2UgZ3JpZCB0b3BvbG9neS4gSXQgYWNjZXB0cyB2YXJpb3VzIHF1ZXJ5IHBhcmFtZXRlcnMgc3VjaCBhczogLSBgbGltaXRgIC0gYG9mZnNldGBcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEhhc2h0YWdzVG9jKHBhcmFtczogWC5SZWFkSGFzaHRhZ3NUb2NRdWVyeSk6IERhdGFTdGF0ZTxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4oJy9oYXNodGFncy90b2MnLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEhhc2h0YWdzVG9jMihwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPignL2hhc2h0YWdzL3RvYycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRpbmcgYSBzaW5nbGUgSGFzaHRhZ1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIHVwZGF0ZSBhIHNpbmdsZSBIYXNodGFnIGluc3RhbmNlIHdpdGggYSBsaXN0IG9mIGBjYXJkX2lkc2AgdG8gd2hpY2ggaXQgc2hvdWxkIGdldCBhdHRhY2hlZCB0by5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlSGFzaHRhZyhoYXNodGFnSWQ6IGFueSwgYm9keTogWC5VcGRhdGVIYXNodGFnQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVIYXNodGFnUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlSGFzaHRhZ1Jlc3BvbnNlPihgL2hhc2h0YWdzLyR7aGFzaHRhZ0lkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBJbnRlcm5hbCBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9pbnRlcm5hbC5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSW50ZXJuYWxEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ2xlYXIgYWxsIEVudHJpZXMgZm9yIGEgZ2l2ZW4gVXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEludGVybmFsIHZpZXcgZW5hYmxpbmcgb25lIHRvIGNsZWFuIHVwIGFsbCBkYXRhYmFzZSBlbnRyaWVzIGZvciBhIHNwZWNpZmljIGB1c2VyX2lkYC4gSXQgbXVzdCBiZSBvZiB0aGUgdXRtb3N0IGltcG9ydGFuY2UgdGhhdCB0aGlzIGVuZHBvaW50IHdvdWxkIG5vdCBiZSBhdmFpbGFibGUgb24gdGhlIHByb2R1Y3Rpb24gc3lzdGVtLlxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVFbnRyaWVzRm9yVXNlcih1c2VySWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVFbnRyaWVzRm9yVXNlclJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkRlbGV0ZUVudHJpZXNGb3JVc2VyUmVzcG9uc2U+KGAvcmVzZXQvJHt1c2VySWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEludm9pY2UgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vaW52b2ljZXMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEludm9pY2VzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgYWxsIEludm9pY2VzIGJlbG9uZ2luZyB0byBhIGdpdmVuIHVzZXJcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIHRoZSB0aGUgVXNlciB0byBsaXN0IGFsbCBvZiB0aGUgSW52b2ljZXMgd2hpY2ggd2VyZSBnZW5lcmF0ZWQgZm9yIGhpcyBEb25hdGlvbnMgb3IgU3Vic2NyaXB0aW9uIHBheW1lbnRzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEludm9pY2VzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXltZW50cy9pbnZvaWNlcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkSW52b2ljZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+KCcvcGF5bWVudHMvaW52b2ljZXMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FsY3VsYXRlIGRlYnQgZm9yIGEgZ2l2ZW4gdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENhbGN1bGF0ZSBkZWJ0IGZvciBhIGdpdmVuIHVzZXIgYnkgc2VhcmNoaW5nIGZvciB0aGUgbGF0ZXN0IHVucGFpZCBpbnZvaWNlLiBJdCByZXR1cm5zIHBheW1lbnQgdG9rZW4gd2hpY2ggY2FuIGJlIHVzZWQgaW4gdGhlIFBBSURfV0lUSF9ERUZBVUxUX1BBWU1FTlRfQ0FSRCBjb21tYW5kXG4gICAgICovXG4gICAgcHVibGljIGNhbGN1bGF0ZURlYnQoKTogRGF0YVN0YXRlPFguQ2FsY3VsYXRlRGVidFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5DYWxjdWxhdGVEZWJ0UmVzcG9uc2U+KCcvcGF5bWVudHMvaW52b2ljZXMvZGVidC8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGNhbGN1bGF0ZURlYnQyKCk6IE9ic2VydmFibGU8WC5DYWxjdWxhdGVEZWJ0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4oJy9wYXltZW50cy9pbnZvaWNlcy9kZWJ0LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogSW52b2ljZSBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL2ludm9pY2UucHkvI2xpbmVzLTUzXG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlQ3VycmVuY3kge1xuICAgIFBMTiA9ICdQTE4nLFxufVxuXG5leHBvcnQgZW51bSBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUVudGl0eSB7XG4gICAgYW1vdW50OiBzdHJpbmc7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBjdXJyZW5jeT86IHN0cmluZztcbiAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIGlzX2V4dGVuc2lvbj86IGJvb2xlYW47XG4gICAgcGFpZF90aWxsX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgY3VycmVuY3k/OiBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgZGlzcGxheV9wcmljZTogc3RyaW5nO1xuICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0X3R5cGU6IEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgIH07XG4gICAgc3VycGx1c19hbW91bnQ/OiBzdHJpbmc7XG4gICAgc3VycGx1c19jdXJyZW5jeT86IHN0cmluZztcbiAgICB2YWxpZF90aWxsX3RpbWVzdGFtcDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZSB7XG4gICAgZGF0YTogQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvaW52b2ljZS5weS8jbGluZXMtNTFcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENhbGN1bGF0ZURlYnRSZXNwb25zZSB7XG4gICAgYXRfX2NvbW1hbmRzOiBPYmplY3Q7XG4gICAgY3VycmVuY3k6IHN0cmluZztcbiAgICBkaXNwbGF5X293ZXM6IHN0cmluZztcbiAgICBvd2VzOiBudW1iZXI7XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBMaW5rcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9saW5rcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTGlua3NEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIExpbmtcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZW1vdmUgYSBMaW5rIGJldHdlZW4gdHdvIGNhcmRzLlxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVMaW5rKGZyb21DYXJkSWQ6IGFueSwgdG9DYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVMaW5rUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlTGlua1Jlc3BvbnNlPihgL2dyaWQvbGlua3MvJHtmcm9tQ2FyZElkfS8ke3RvQ2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBvciBDcmVhdGUgTGlua1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgb3IgQ3JlYXRlIGEgTGluayBiZXR3ZWVuIHR3byBjYXJkcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE9yQ3JlYXRlTGluayhib2R5OiBYLlJlYWRPckNyZWF0ZUxpbmtCb2R5KTogT2JzZXJ2YWJsZTxYLlJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlPignL2dyaWQvbGlua3MvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIExpbmtzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvYjhkZWMzY2YxM2QxODk3MTA5MjIwNzg3Zjk5NTU0NjU1OGRlNDc3ZC9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRGVsZXRlTGlua1Jlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvYjhkZWMzY2YxM2QxODk3MTA5MjIwNzg3Zjk5NTU0NjU1OGRlNDc3ZC9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS9ncmlkL3ZpZXdzLnB5LyNsaW5lcy00N1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVhZE9yQ3JlYXRlTGlua0JvZHkge1xuICAgIGZyb21fY2FyZF9pZDogbnVtYmVyO1xuICAgIHRvX2NhcmRfaWQ6IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy9iOGRlYzNjZjEzZDE4OTcxMDkyMjA3ODdmOTk1NTQ2NTU4ZGU0NzdkL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL2dyaWQvc2VyaWFsaXplcnMucHkvI2xpbmVzLThcbiAqL1xuXG5leHBvcnQgZW51bSBSZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2VLaW5kIHtcbiAgICBDQVJEID0gJ0NBUkQnLFxuICAgIEZSQUdNRU5UID0gJ0ZSQUdNRU5UJyxcbiAgICBIQVNIVEFHID0gJ0hBU0hUQUcnLFxuICAgIFBBVEggPSAnUEFUSCcsXG4gICAgVEVSTSA9ICdURVJNJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBSZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2Uge1xuICAgIGF1dGhvcl9pZD86IGFueTtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGZyb21fY2FyZF9pZD86IGFueTtcbiAgICBpZD86IG51bWJlcjtcbiAgICBraW5kOiBSZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2VLaW5kO1xuICAgIHJlZmVyZW5jZV9pZDogbnVtYmVyO1xuICAgIHRvX2NhcmRfaWQ/OiBhbnk7XG4gICAgdmFsdWU6IG51bWJlcjtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIE1lZGlhSXRlbXMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vbWVkaWFpdGVtcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTWVkaWFpdGVtc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IE1lZGlhSXRlbXNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IE1lZGlhSXRlbXNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRNZWRpYWl0ZW1zKHBhcmFtczogWC5CdWxrUmVhZE1lZGlhaXRlbXNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkTWVkaWFpdGVtc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkTWVkaWFpdGVtc1Jlc3BvbnNlRW50aXR5W10+KCcvbWVkaWFpdGVtcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRNZWRpYWl0ZW1zMihwYXJhbXM6IFguQnVsa1JlYWRNZWRpYWl0ZW1zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4oJy9tZWRpYWl0ZW1zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZlIE1lZGlhSXRlbVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbW92ZSBNZWRpYUl0ZW0gaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55LCBwYXJhbXM6IFguRGVsZXRlTWVkaWFpdGVtUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlTWVkaWFpdGVtUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy8ke21lZGlhaXRlbUlkfWAsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIE1lZGlhSXRlbVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgTWVkaWFJdGVtXG4gICAgICovXG4gICAgcHVibGljIHJlYWRNZWRpYWl0ZW0obWVkaWFpdGVtSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPihgL21lZGlhaXRlbXMvJHttZWRpYWl0ZW1JZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRNZWRpYWl0ZW0yKG1lZGlhaXRlbUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy8ke21lZGlhaXRlbUlkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgQnkgUHJvY2VzcyBJZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgTWVkaWFJdGVtIGJ5IFByb2Nlc3MgSWRcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkKHByb2Nlc3NJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPihgL21lZGlhaXRlbXMvYnlfcHJvY2Vzcy8ke3Byb2Nlc3NJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZDIocHJvY2Vzc0lkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPihgL21lZGlhaXRlbXMvYnlfcHJvY2Vzcy8ke3Byb2Nlc3NJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIG9yIENyZWF0ZSBNZWRpYUl0ZW1cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIG9yIENyZWF0ZSBNZWRpYUl0ZW0gaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRPckNyZWF0ZU1lZGlhaXRlbShib2R5OiBYLlJlYWRPckNyZWF0ZU1lZGlhaXRlbUJvZHkpOiBPYnNlcnZhYmxlPFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlJlYWRPckNyZWF0ZU1lZGlhaXRlbVJlc3BvbnNlPignL21lZGlhaXRlbXMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgTWVkaWFJdGVtXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIE1lZGlhSXRlbSBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnksIGJvZHk6IFguVXBkYXRlTWVkaWFpdGVtQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVNZWRpYWl0ZW1SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgTWVkaWFJdGVtIFJlcHJlc2VudGF0aW9uXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIGdpdmVuIE1lZGlhSXRlbSB3aXRoIG9ubHkgdGhlIGZpZWxkcyB3aGljaCBhcmUgZGVjaWRlZCBleHRlcm5hbGx5ICh1c2luZyBleHRlcm5hbCBzZXJ2aWNlcykuIEZpZWxkcyBsaWtlOiAtIGB3ZWJfcmVwcmVzZW50YXRpb25zYCAtIGB0aHVtYm5haWxfdXJpYCAtIGBtZXRhYCAtIGB0ZXh0YCBBbGwgb2YgdGhvc2UgZmllbGRzIGFyZSBjb21wdXRlZCBpbiBzbWFydGVyIHdheSBpbiBvcmRlciB0byBtYWtlIHRoZSBNZWRpYUl0ZW0gd2F5IGJldHRlciBpbiBhIHNlbWFudGljIHNlbnNlLiBUaG9zZSBmaWVsZHMgYXJlIHBlcmNlaXZlZCBhcyB0aGUgYHJlcHJlc2VudGF0aW9uYCBvZiBhIGdpdmVuIE1lZGlhSXRlbSBzaW5jZSB0aGV5IGNvbnRhaW5zIGluZm9ybWF0aW9uIGFib3V0IGhvdyB0byBkaXNwbGF5IGEgZ2l2ZW4gTWVkaWFJdGVtLCBob3cgdG8gdW5kZXJzdGFuZCBpdCBldGMuIEl0IGdvZXMgYmV5b25kIHRoZSBzaW1wbGUgYWJzdHJhY3QgZGF0YSBvcmllbnRlZCByZXByZXNlbnRhdGlvbiAodXJpLCBleHRlbnNpb24gZXRjLikuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uKG1lZGlhaXRlbUlkOiBhbnksIGJvZHk6IFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9L3JlcHJlc2VudGF0aW9uL2AsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBOb3RpZmljYXRpb24gTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vbm90aWZpY2F0aW9ucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTm90aWZpY2F0aW9uc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBY2tub3dsZWRnZSBOb3RpZmljYXRpb25cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBBY2tub3dsZWRnZSBOb3RpZmljYXRpb25cbiAgICAgKi9cbiAgICBwdWJsaWMgYWNrbm93bGVkZ2VOb3RpZmljYXRpb24obm90aWZpY2F0aW9uSWQ6IGFueSk6IE9ic2VydmFibGU8WC5BY2tub3dsZWRnZU5vdGlmaWNhdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLkFja25vd2xlZGdlTm90aWZpY2F0aW9uUmVzcG9uc2U+KGAvbm90aWZpY2F0aW9ucy8ke25vdGlmaWNhdGlvbklkfS9hY2tub3dsZWRnZS9gLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IE5vdGlmaWNhdGlvbnNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IE5vdGlmaWNhdGlvbnNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWROb3RpZmljYXRpb25zKHBhcmFtczogWC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W10+KCcvbm90aWZpY2F0aW9ucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWROb3RpZmljYXRpb25zMihwYXJhbXM6IFguQnVsa1JlYWROb3RpZmljYXRpb25zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4oJy9ub3RpZmljYXRpb25zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBOb3RpZmljYXRpb24gTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWZyYWdtZW50LXNlcnZpY2Uvc3JjL2IwMjNhZDVkYTE1MDI3NjgzMDI4NjA5YzE0MDI2MGIwYTE4MDg0NTIvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEFja25vd2xlZGdlTm90aWZpY2F0aW9uUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWZyYWdtZW50LXNlcnZpY2Uvc3JjL2IwMjNhZDVkYTE1MDI3NjgzMDI4NjA5YzE0MDI2MGIwYTE4MDg0NTIvY29zcGhlcmVfZnJhZ21lbnRfc2VydmljZS9ub3RpZmljYXRpb24vdmlld3MucHkvI2xpbmVzLTc3XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSB7XG4gICAgYWNrbm93bGVkZ2VkPzogYm9vbGVhbjtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcF9fZ3Q/OiBudW1iZXI7XG4gICAgbGltaXQ/OiBudW1iZXI7XG4gICAgb2Zmc2V0PzogbnVtYmVyO1xuICAgIHVwZGF0ZWRfdGltZXN0YW1wX19ndD86IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWZyYWdtZW50LXNlcnZpY2Uvc3JjL2IwMjNhZDVkYTE1MDI3NjgzMDI4NjA5YzE0MDI2MGIwYTE4MDg0NTIvY29zcGhlcmVfZnJhZ21lbnRfc2VydmljZS9ub3RpZmljYXRpb24vc2VyaWFsaXplcnMucHkvI2xpbmVzLTQ2XG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VLaW5kIHtcbiAgICBGUkFHTUVOVF9VUERBVEUgPSAnRlJBR01FTlRfVVBEQVRFJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eSB7XG4gICAgYWNrbm93bGVkZ2VkOiBib29sZWFuO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAga2luZDogQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VLaW5kO1xuICAgIHBheWxvYWQ6IE9iamVjdDtcbiAgICB1cGRhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlIHtcbiAgICBkYXRhOiBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUGF0aHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcGF0aHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFBhdGhzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIERlbGV0ZSBQYXRoc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuZHBvaW50IGZvciBEZWxldGluZyBtdWx0aXBsZSBQYXRocy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa0RlbGV0ZVBhdGhzKHBhcmFtczogWC5CdWxrRGVsZXRlUGF0aHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrRGVsZXRlUGF0aHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5CdWxrRGVsZXRlUGF0aHNSZXNwb25zZT4oJy9wYXRocy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBQYXRoc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgYWxsIHVzZXIncyBQYXRoc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFBhdGhzKHBhcmFtczogWC5CdWxrUmVhZFBhdGhzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+KCcvcGF0aHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAncGF0aHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFBhdGhzMihwYXJhbXM6IFguQnVsa1JlYWRQYXRoc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXRocy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdwYXRocycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgUGF0aFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuZHBvaW50IGZvciBDcmVhdGluZyBQYXRoLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVQYXRoKGJvZHk6IFguQ3JlYXRlUGF0aEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVQYXRoUmVzcG9uc2U+KCcvcGF0aHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIFBhdGhcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIHNpbmdsZSBQYXRoXG4gICAgICovXG4gICAgcHVibGljIHJlYWRQYXRoKHBhdGhJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZFBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZFBhdGhSZXNwb25zZT4oYC9wYXRocy8ke3BhdGhJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRQYXRoMihwYXRoSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkUGF0aFJlc3BvbnNlPihgL3BhdGhzLyR7cGF0aElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBQYXRoXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5kcG9pbnQgZm9yIFVwZGF0aW5nIFBhdGguXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZVBhdGgocGF0aElkOiBhbnksIGJvZHk6IFguVXBkYXRlUGF0aEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZVBhdGhSZXNwb25zZT4oYC9wYXRocy8ke3BhdGhJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUGF5bWVudCBDYXJkcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9wYXltZW50X2NhcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBQYXltZW50Q2FyZHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTWFyayBhIGdpdmVuIFBheW1lbnQgQ2FyZCBhcyBhIGRlZmF1bHQgb25lXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gbWFyayBhIHNwZWNpZmljIFBheW1lbnQgQ2FyZCBhcyBhIGRlZmF1bHQgb25lLCBtZWFuaW5nIHRoYXQgaXQgd2lsbCBiZSB1c2VkIGZvciBhbGwgdXBjb21pbmcgcGF5bWVudHMuIE1hcmtpbmcgUGF5bWVudCBDYXJkIGFzIGEgZGVmYXVsdCBvbmUgYXV0b21hdGljYWxseSBsZWFkcyB0byB0aGUgdW5tYXJraW5nIG9mIGFueSBQYXltZW50IENhcmQgd2hpY2ggd2FzIGRlZmF1bHQgb25lIGJlZm9yZSB0aGUgaW52b2NhdGlvbiBvZiB0aGUgY29tbWFuZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgYXNEZWZhdWx0TWFya1BheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5Bc0RlZmF1bHRNYXJrUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5Bc0RlZmF1bHRNYXJrUGF5bWVudGNhcmRSZXNwb25zZT4oYC9wYXltZW50cy9wYXltZW50X2NhcmRzLyR7cGF5bWVudENhcmRJZH0vbWFya19hc19kZWZhdWx0L2AsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgYWxsIFBheW1lbnQgQ2FyZHMgYmVsb25naW5nIHRvIGEgZ2l2ZW4gdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIGxpc3QgYWxsIG9mIHRoZSBQYXltZW50IENhcmRzIHdoaWNoIHdlcmUgYWRkZWQgYnkgaGltIC8gaGVyLiBBbW9uZyBhbGwgcmV0dXJuZWQgUGF5bWVudCBDYXJkcyB0aGVyZSBtdXN0IGJlIG9uZSBhbmQgb25seSBvbmUgd2hpY2ggaXMgbWFya2VkIGFzICoqZGVmYXVsdCoqLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFBheW1lbnRjYXJkcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRQYXltZW50Y2FyZHMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIFBheW1lbnQgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIGFkZCBuZXcgUGF5bWVudCBDYXJkLCB3aGljaCBjb3VsZCBiZSBuZWVkZWQgaW4gY2FzZXMgd2hlbiB0aGUgVXNlciB3b3VsZCBsaWtlIHRvIHJlcGxhY2UgZXhpc3RpbmcgUGF5bWVudCBDYXJkIGJlY2F1c2U6IC0gaXQgZXhwaXJlZCAtIGlzIGVtcHR5IC0gdGhlIFVzZXIgcHJlZmVycyBhbm90aGVyIG9uZSB0byBiZSB1c2VkIGZyb20gbm93IG9uLiBVc2luZyB0aGUgb3B0aW9uYWwgYG1hcmtfYXNfZGVmYXVsdGAgZmllbGQgb25lIGNhbiBtYXJrIGp1c3QgY3JlYXRlZCBQYXltZW50IENhcmQgYXMgdGhlIGRlZmF1bHQgb25lLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVQYXltZW50Y2FyZChib2R5OiBYLkNyZWF0ZVBheW1lbnRjYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlPignL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgYSBnaXZlbiBQYXltZW50IENhcmQgYmVsb25naW5nIHRvIGEgZ2l2ZW4gdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIHJlbW92ZSBhIHNwZWNpZmljIFBheW1lbnQgQ2FyZCB3aGljaCB3ZXJlIGFkZGVkIGJ5IGhpbSAvIGhlci4gUGF5bWVudCBDYXJkIGNhbiBiZSByZW1vdmVkIG9ubHkgaWYgaXQncyBub3QgYSBkZWZhdWx0IG9uZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlUGF5bWVudGNhcmQocGF5bWVudENhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZVBheW1lbnRjYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlUGF5bWVudGNhcmRSZXNwb25zZT4oYC9wYXltZW50cy9wYXltZW50X2NhcmRzLyR7cGF5bWVudENhcmRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBheSB1c2luZyB0aGUgZGVmYXVsdCBQYXltZW50IENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVc2VyIGlzIGFsbG93ZWQgb25seSB0byBwZXJmb3JtIHBheW1lbnRzIGFnYWluc3QgaGVyIGRlZmF1bHQgUGF5bWVudCBDYXJkLiBJbiBvdGhlciB3b3JkcyBvbiBvcmRlciB0byB1c2UgYSBnaXZlbiBQYXltZW50IENhcmQgb25lIGhhcyB0byBtYXJrIGlzIGFzIGRlZmF1bHQuIEFsc28gb25lIGlzIG5vdCBhbGxvd2VkIHRvIHBlcmZvcm0gc3VjaCBwYXltZW50cyBmcmVlbHkgYW5kIHRoZXJlZm9yZSB3ZSBleHBlY3QgdG8gZ2V0IGEgYHBheW1lbnRfdG9rZW5gIGluc2lkZSB3aGljaCBhbm90aGVyIHBpZWNlIG9mIG91ciBzeXN0ZW0gZW5jb2RlZCBhbGxvd2VkIHN1bSB0byBiZSBwYWlkLlxuICAgICAqL1xuICAgIHB1YmxpYyBwYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkKGJvZHk6IFguUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5QYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2U+KCcvcGF5bWVudHMvcGF5bWVudF9jYXJkcy9wYXlfd2l0aF9kZWZhdWx0LycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGEgUGF5bWVudCBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gYWRkIG5ldyBQYXltZW50IENhcmQsIHdoaWNoIGNvdWxkIGJlIG5lZWRlZCBpbiBjYXNlcyB3aGVuIHRoZSBVc2VyIHdvdWxkIGxpa2UgdG8gcmVwbGFjZSBleGlzdGluZyBQYXltZW50IENhcmQgYmVjYXVzZTogLSBpdCBleHBpcmVkIC0gaXMgZW1wdHkgLSB0aGUgVXNlciBwcmVmZXJzIGFub3RoZXIgb25lIHRvIGJlIHVzZWQgZnJvbSBub3cgb25cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVuZGVyUGF5bWVudENhcmRXaWRnZXQoKTogRGF0YVN0YXRlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzL3dpZGdldC8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlbmRlclBheW1lbnRDYXJkV2lkZ2V0MigpOiBPYnNlcnZhYmxlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzL3dpZGdldC8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFBheW1lbnQgQ2FyZHMgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQXNEZWZhdWx0TWFya1BheW1lbnRjYXJkUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9wYXltZW50X2NhcmQucHkvI2xpbmVzLTc1XG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VTdGF0dXMge1xuICAgIENBTkNFTEVEID0gJ0NBTkNFTEVEJyxcbiAgICBDT01QTEVURUQgPSAnQ09NUExFVEVEJyxcbiAgICBORVcgPSAnTkVXJyxcbiAgICBQRU5ESU5HID0gJ1BFTkRJTkcnLFxuICAgIFJFSkVDVEVEID0gJ1JFSkVDVEVEJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBleHBpcmF0aW9uX21vbnRoPzogbnVtYmVyO1xuICAgIGV4cGlyYXRpb25feWVhcj86IG51bWJlcjtcbiAgICBleHBpcmVkOiBib29sZWFuO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIGlzX2RlZmF1bHQ/OiBib29sZWFuO1xuICAgIGlzX2Z1bGx5X2RlZmluZWQ6IGJvb2xlYW47XG4gICAgbWFza2VkX251bWJlcjogc3RyaW5nO1xuICAgIHBheW1lbnRzOiB7XG4gICAgICAgIGFtb3VudDogc3RyaW5nO1xuICAgICAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgICAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0OiB7XG4gICAgICAgICAgICBjdXJyZW5jeT86IEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICAgICAgcHJvZHVjdF90eXBlOiBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgICAgIH07XG4gICAgICAgIHN0YXR1cz86IEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VTdGF0dXM7XG4gICAgICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG4gICAgfVtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2Uge1xuICAgIGRhdGE6IEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9wYXltZW50X2NhcmQucHkvI2xpbmVzLTUyXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVQYXltZW50Y2FyZEJvZHkge1xuICAgIGV4cGlyYXRpb25fbW9udGg6IG51bWJlcjtcbiAgICBleHBpcmF0aW9uX3llYXI6IG51bWJlcjtcbiAgICBtYXJrX2FzX2RlZmF1bHQ/OiBib29sZWFuO1xuICAgIG1hc2tlZF9udW1iZXI6IHN0cmluZztcbiAgICB0b2tlbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnRfY2FyZC5weS8jbGluZXMtOVxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlU3RhdHVzIHtcbiAgICBDQU5DRUxFRCA9ICdDQU5DRUxFRCcsXG4gICAgQ09NUExFVEVEID0gJ0NPTVBMRVRFRCcsXG4gICAgTkVXID0gJ05FVycsXG4gICAgUEVORElORyA9ICdQRU5ESU5HJyxcbiAgICBSRUpFQ1RFRCA9ICdSRUpFQ1RFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZSB7XG4gICAgZXhwaXJhdGlvbl9tb250aD86IG51bWJlcjtcbiAgICBleHBpcmF0aW9uX3llYXI/OiBudW1iZXI7XG4gICAgZXhwaXJlZDogYm9vbGVhbjtcbiAgICBpZD86IG51bWJlcjtcbiAgICBpc19kZWZhdWx0PzogYm9vbGVhbjtcbiAgICBpc19mdWxseV9kZWZpbmVkOiBib29sZWFuO1xuICAgIG1hc2tlZF9udW1iZXI6IHN0cmluZztcbiAgICBwYXltZW50czoge1xuICAgICAgICBhbW91bnQ6IHN0cmluZztcbiAgICAgICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICAgICAgZGlzcGxheV9hbW91bnQ6IHN0cmluZztcbiAgICAgICAgcHJvZHVjdDoge1xuICAgICAgICAgICAgY3VycmVuY3k/OiBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgICAgIHByb2R1Y3RfdHlwZTogQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgICAgICB9O1xuICAgICAgICBzdGF0dXM/OiBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlU3RhdHVzO1xuICAgICAgICBzdGF0dXNfbGVkZ2VyPzogT2JqZWN0O1xuICAgIH1bXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRGVsZXRlUGF5bWVudGNhcmRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL3BheW1lbnRfY2FyZC5weS8jbGluZXMtMjA0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkQm9keSB7XG4gICAgcGF5bWVudF90b2tlbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnQucHkvI2xpbmVzLTlcbiAqL1xuXG5leHBvcnQgZW51bSBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBlbnVtIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVN0YXR1cyB7XG4gICAgQ0FOQ0VMRUQgPSAnQ0FOQ0VMRUQnLFxuICAgIENPTVBMRVRFRCA9ICdDT01QTEVURUQnLFxuICAgIE5FVyA9ICdORVcnLFxuICAgIFBFTkRJTkcgPSAnUEVORElORycsXG4gICAgUkVKRUNURUQgPSAnUkVKRUNURUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZSB7XG4gICAgYW1vdW50OiBzdHJpbmc7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgY3VycmVuY3k/OiBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgZGlzcGxheV9wcmljZTogc3RyaW5nO1xuICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0X3R5cGU6IFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVByb2R1Y3RUeXBlO1xuICAgIH07XG4gICAgc3RhdHVzPzogUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlU3RhdHVzO1xuICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvbW9kZWxzL3BheXUucHkvI2xpbmVzLTMxM1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZSB7XG4gICAgY3VycmVuY3lfY29kZTogc3RyaW5nO1xuICAgIGN1c3RvbWVyX2VtYWlsPzogc3RyaW5nO1xuICAgIGN1c3RvbWVyX2xhbmd1YWdlOiBzdHJpbmc7XG4gICAgbWVyY2hhbnRfcG9zX2lkOiBzdHJpbmc7XG4gICAgcmVjdXJyaW5nX3BheW1lbnQ6IGJvb2xlYW47XG4gICAgc2hvcF9uYW1lOiBzdHJpbmc7XG4gICAgc2lnOiBzdHJpbmc7XG4gICAgc3RvcmVfY2FyZDogYm9vbGVhbjtcbiAgICB0b3RhbF9hbW91bnQ6IHN0cmluZztcbiAgICB3aWRnZXRfbW9kZT86IHN0cmluZztcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFBheW1lbnRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3BheW1lbnRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBQYXltZW50c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgdGhlIHN0YXR1cyBvZiBhIGdpdmVuIFBheW1lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgdGhlIFBheW1lbnQgaW5zdGFuY2UgaWRlbnRpZmllZCBieSB0aGUgYHNlc3Npb25faWRgLiBUaGlzIGNvbW1hbmQgaXMgZm9yIGV4dGVybmFsIHVzZSBvbmx5IHRoZXJlZm9yZSBpdCBkb2Vzbid0IGV4cG9zZSBpbnRlcm5hbCBpZHMgb2YgdGhlIHBheW1lbnRzIGJ1dCByYXRoZXIgc2Vzc2lvbiBpZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlUGF5bWVudFN0YXR1cyhib2R5OiBYLlVwZGF0ZVBheW1lbnRTdGF0dXNCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVBheW1lbnRTdGF0dXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguVXBkYXRlUGF5bWVudFN0YXR1c1Jlc3BvbnNlPignL3BheW1lbnRzLyg/UDxzZXNzaW9uX2lkPltcXHdcXC1dKyknLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFJlY2FsbCBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9yZWNhbGwubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFJlY2FsbERvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgUmVjYWxsIFNlc3Npb25cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZW5kZXIgUmVjYWxsIFNlc3Npb24gY29tcG9zZWQgb3V0IG9mIHRoZSBzZXF1ZW5jZSBvZiBDYXJkcyB0aGF0IHNob3VsZCBiZSByZWNhbGxlZCBpbiBhIGdpdmVuIG9yZGVyLiBCYXNlZCBvbiB0aGUgUmVjYWxsQXR0ZW1wdCBzdGF0cyByZWNvbW1lbmQgYW5vdGhlciBDYXJkIHRvIHJlY2FsbCBpbiBvcmRlciB0byBtYXhpbWl6ZSB0aGUgcmVjYWxsIHNwZWVkIGFuZCBzdWNjZXNzIHJhdGUuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZVJlY2FsbFNlc3Npb24oYm9keTogWC5DcmVhdGVSZWNhbGxTZXNzaW9uQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVSZWNhbGxTZXNzaW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZVJlY2FsbFNlc3Npb25SZXNwb25zZT4oJy9yZWNhbGwvc2Vzc2lvbnMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIFJlY2FsbCBTdW1tYXJ5XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBzdW1tYXJ5IHN0YXRzIGZvciBjYXJkcyBhbmQgdGhlaXIgcmVjYWxsX3Njb3JlIGZvciBhIGdpdmVuIFVzZXIuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRSZWNhbGxTdW1tYXJ5KCk6IERhdGFTdGF0ZTxYLlJlYWRSZWNhbGxTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRSZWNhbGxTdW1tYXJ5UmVzcG9uc2U+KCcvcmVjYWxsL3N1bW1hcnkvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkUmVjYWxsU3VtbWFyeTIoKTogT2JzZXJ2YWJsZTxYLlJlYWRSZWNhbGxTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRSZWNhbGxTdW1tYXJ5UmVzcG9uc2U+KCcvcmVjYWxsL3N1bW1hcnkvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBTdWJzY3JpcHRpb24gTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vc3Vic2NyaXB0aW9ucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgU3Vic2NyaXB0aW9uc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZXF1ZXN0IGEgc3Vic2NyaXB0aW9uIGNoYW5nZVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFdoZW5ldmVyIHRoZSB1c2VyIHdhbnRzIHRvIGNoYW5nZSBoZXIgc3Vic2NyaXB0aW9uIGl0IG11c3QgaGFwcGVuIHRocm91Z2ggdGhpcyBlbmRwb2ludC4gSXQncyBzdGlsbCBwb3NzaWJsZSB0aGF0IHRoZSBzdWJzY3JpcHRpb24gd2lsbCBjaGFuZ2Ugd2l0aG91dCB1c2VyIGFza2luZyBmb3IgaXQsIGJ1dCB0aGF0IGNhbiBoYXBwZW4gd2hlbiBkb3duZ3JhZGluZyBkdWUgdG8gbWlzc2luZyBwYXltZW50LlxuICAgICAqL1xuICAgIHB1YmxpYyBjaGFuZ2VTdWJzY3JpcHRpb24oYm9keTogWC5DaGFuZ2VTdWJzY3JpcHRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNoYW5nZVN1YnNjcmlwdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLkNoYW5nZVN1YnNjcmlwdGlvblJlc3BvbnNlPignL3BheW1lbnRzL3N1YnNjcmlwdGlvbi8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogU3Vic2NyaXB0aW9uIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3Mvc3Vic2NyaXB0aW9uLnB5LyNsaW5lcy0yOFxuICovXG5cbmV4cG9ydCBlbnVtIENoYW5nZVN1YnNjcmlwdGlvbkJvZHlTdWJzY3JpcHRpb25UeXBlIHtcbiAgICBGUkVFID0gJ0ZSRUUnLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENoYW5nZVN1YnNjcmlwdGlvbkJvZHkge1xuICAgIHN1YnNjcmlwdGlvbl90eXBlOiBDaGFuZ2VTdWJzY3JpcHRpb25Cb2R5U3Vic2NyaXB0aW9uVHlwZTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9zdWJzY3JpcHRpb24ucHkvI2xpbmVzLTM5XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDaGFuZ2VTdWJzY3JpcHRpb25SZXNwb25zZSB7XG4gICAgYXRfX3Byb2Nlc3M6IE9iamVjdDtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFRhc2tzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3Rhc2tzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBUYXNrc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFRhc2tzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCB0YXNrc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFRhc2tzKHBhcmFtczogWC5CdWxrUmVhZFRhc2tzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkVGFza3MyKHBhcmFtczogWC5CdWxrUmVhZFRhc2tzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPignL3Rhc2tzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBUYXNrIEJpbnNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFRhc2tzIEJpbnNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrQmlucyhwYXJhbXM6IFguQnVsa1JlYWRUYXNrQmluc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdPignL3Rhc2tzL2JpbnMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkVGFza0JpbnMyKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdPignL3Rhc2tzL2JpbnMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFRhc2tzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvYjhkZWMzY2YxM2QxODk3MTA5MjIwNzg3Zjk5NTU0NjU1OGRlNDc3ZC9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS90YXNrL3ZpZXdzLnB5LyNsaW5lcy0zM1xuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkVGFza3NRdWVyeVF1ZXVlVHlwZSB7XG4gICAgRE4gPSAnRE4nLFxuICAgIEhQID0gJ0hQJyxcbiAgICBPVCA9ICdPVCcsXG4gICAgUFIgPSAnUFInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza3NRdWVyeSB7XG4gICAgYXNjZW5kaW5nPzogYm9vbGVhbjtcbiAgICBsaW1pdD86IG51bWJlcjtcbiAgICBvZmZzZXQ/OiBudW1iZXI7XG4gICAgcXVldWVfdHlwZT86IEJ1bGtSZWFkVGFza3NRdWVyeVF1ZXVlVHlwZTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy9iOGRlYzNjZjEzZDE4OTcxMDkyMjA3ODdmOTk1NTQ2NTU4ZGU0NzdkL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL3Rhc2svc2VyaWFsaXplcnMucHkvI2xpbmVzLTU1XG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRUYXNrc1Jlc3BvbnNlUXVldWVUeXBlIHtcbiAgICBETiA9ICdETicsXG4gICAgSFAgPSAnSFAnLFxuICAgIE9UID0gJ09UJyxcbiAgICBQUiA9ICdQUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBhcmNoaXZlZD86IGJvb2xlYW47XG4gICAgY29udGVudD86IE9iamVjdDtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGRvbmVfZGF0ZTogc3RyaW5nO1xuICAgIGRvbmVfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgb3JkZXJfbnVtYmVyPzogbnVtYmVyO1xuICAgIHF1ZXVlX3R5cGU/OiBCdWxrUmVhZFRhc2tzUmVzcG9uc2VRdWV1ZVR5cGU7XG4gICAgdG90YWxfdGltZT86IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tzUmVzcG9uc2Uge1xuICAgIGRhdGE6IEJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjL2I4ZGVjM2NmMTNkMTg5NzEwOTIyMDc4N2Y5OTU1NDY1NThkZTQ3N2QvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvdGFzay92aWV3cy5weS8jbGluZXMtMzNcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZFRhc2tCaW5zUXVlcnlRdWV1ZVR5cGUge1xuICAgIEROID0gJ0ROJyxcbiAgICBIUCA9ICdIUCcsXG4gICAgT1QgPSAnT1QnLFxuICAgIFBSID0gJ1BSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tCaW5zUXVlcnkge1xuICAgIGFzY2VuZGluZz86IGJvb2xlYW47XG4gICAgbGltaXQ/OiBudW1iZXI7XG4gICAgb2Zmc2V0PzogbnVtYmVyO1xuICAgIHF1ZXVlX3R5cGU/OiBCdWxrUmVhZFRhc2tCaW5zUXVlcnlRdWV1ZVR5cGU7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvYjhkZWMzY2YxM2QxODk3MTA5MjIwNzg3Zjk5NTU0NjU1OGRlNDc3ZC9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS90YXNrL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy03MVxuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZVF1ZXVlVHlwZSB7XG4gICAgRE4gPSAnRE4nLFxuICAgIEhQID0gJ0hQJyxcbiAgICBPVCA9ICdPVCcsXG4gICAgUFIgPSAnUFInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eSB7XG4gICAgZG9uZV9kYXRlOiBzdHJpbmc7XG4gICAgdGFza3M6IHtcbiAgICAgICAgYXJjaGl2ZWQ/OiBib29sZWFuO1xuICAgICAgICBjb250ZW50PzogT2JqZWN0O1xuICAgICAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgICAgICBkb25lX2RhdGU6IHN0cmluZztcbiAgICAgICAgZG9uZV90aW1lc3RhbXA6IG51bWJlcjtcbiAgICAgICAgaWQ/OiBudW1iZXI7XG4gICAgICAgIG9yZGVyX251bWJlcj86IG51bWJlcjtcbiAgICAgICAgcXVldWVfdHlwZT86IEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZVF1ZXVlVHlwZTtcbiAgICAgICAgdG90YWxfdGltZT86IG51bWJlcjtcbiAgICB9W107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlIHtcbiAgICBkYXRhOiBCdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXTtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFdvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3dvcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBXb3Jkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFdvcmRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBXb3JkcyBieSBmaXJzdCBjaGFyYWN0ZXIuIEl0IGFsbG93cyBvbmUgdG8gZmV0Y2ggbGlzdCBvZiB3b3JkcyBieSBmaXJzdCBjaGFyYWN0ZXIuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkV29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+KCcvd29yZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZhY2FkZSBBUEkgU2VydmljZSBmb3IgYWxsIGRvbWFpbnNcbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSwgSW5qZWN0b3IgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcblxuaW1wb3J0IHsgRGF0YVN0YXRlLCBPcHRpb25zIH0gZnJvbSAnLi9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuLi9kb21haW5zL2luZGV4JztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEFQSVNlcnZpY2Uge1xuXG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBpbmplY3RvcjogSW5qZWN0b3IpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBY2NvdW50IFNldHRpbmdzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfYWNjb3VudF9zZXR0aW5nc0RvbWFpbjogWC5BY2NvdW50U2V0dGluZ3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBhY2NvdW50X3NldHRpbmdzRG9tYWluKCk6IFguQWNjb3VudFNldHRpbmdzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9hY2NvdW50X3NldHRpbmdzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hY2NvdW50X3NldHRpbmdzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5BY2NvdW50U2V0dGluZ3NEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hY2NvdW50X3NldHRpbmdzRG9tYWluO1xuICAgIH1cblxuICAgIHJlYWRBY2NvdW50c2V0dGluZygpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50X3NldHRpbmdzRG9tYWluLnJlYWRBY2NvdW50c2V0dGluZygpO1xuICAgIH1cbiAgICBcbiAgICByZWFkQWNjb3VudHNldHRpbmcyKCk6IE9ic2VydmFibGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50X3NldHRpbmdzRG9tYWluLnJlYWRBY2NvdW50c2V0dGluZzIoKTtcbiAgICB9XG5cbiAgICB1cGRhdGVBY2NvdW50c2V0dGluZyhib2R5OiBYLlVwZGF0ZUFjY291bnRzZXR0aW5nQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRfc2V0dGluZ3NEb21haW4udXBkYXRlQWNjb3VudHNldHRpbmcoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQWNjb3VudHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hY2NvdW50c0RvbWFpbjogWC5BY2NvdW50c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGFjY291bnRzRG9tYWluKCk6IFguQWNjb3VudHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2FjY291bnRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hY2NvdW50c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQWNjb3VudHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hY2NvdW50c0RvbWFpbjtcbiAgICB9XG5cbiAgICBhY3RpdmF0ZUFjY291bnQoYm9keTogWC5BY3RpdmF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkFjdGl2YXRlQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLmFjdGl2YXRlQWNjb3VudChib2R5KTtcbiAgICB9XG5cbiAgICBidWxrUmVhZEFjY291bnRzKHBhcmFtczogWC5CdWxrUmVhZEFjY291bnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5idWxrUmVhZEFjY291bnRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkQWNjb3VudHMyKHBhcmFtczogWC5CdWxrUmVhZEFjY291bnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBY2NvdW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uYnVsa1JlYWRBY2NvdW50czIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBjaGFuZ2VQYXNzd29yZChib2R5OiBYLkNoYW5nZVBhc3N3b3JkQm9keSk6IE9ic2VydmFibGU8WC5DaGFuZ2VQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLmNoYW5nZVBhc3N3b3JkKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUFjY291bnQoYm9keTogWC5DcmVhdGVBY2NvdW50Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uY3JlYXRlQWNjb3VudChib2R5KTtcbiAgICB9XG5cbiAgICByZWFkQWNjb3VudCgpOiBEYXRhU3RhdGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnJlYWRBY2NvdW50KCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRBY2NvdW50MigpOiBPYnNlcnZhYmxlPFguUmVhZEFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5yZWFkQWNjb3VudDIoKTtcbiAgICB9XG5cbiAgICByZXNldFBhc3N3b3JkKGJvZHk6IFguUmVzZXRQYXNzd29yZEJvZHkpOiBPYnNlcnZhYmxlPFguUmVzZXRQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnJlc2V0UGFzc3dvcmQoYm9keSk7XG4gICAgfVxuXG4gICAgc2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWwoYm9keTogWC5TZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5zZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbChib2R5KTtcbiAgICB9XG5cbiAgICBzZW5kUmVzZXRQYXNzd29yZEVtYWlsKGJvZHk6IFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnNlbmRSZXNldFBhc3N3b3JkRW1haWwoYm9keSk7XG4gICAgfVxuXG4gICAgdXBkYXRlQWNjb3VudChib2R5OiBYLlVwZGF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi51cGRhdGVBY2NvdW50KGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEF0dGVtcHQgU3RhdHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hdHRlbXB0X3N0YXRzRG9tYWluOiBYLkF0dGVtcHRTdGF0c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGF0dGVtcHRfc3RhdHNEb21haW4oKTogWC5BdHRlbXB0U3RhdHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2F0dGVtcHRfc3RhdHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2F0dGVtcHRfc3RhdHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkF0dGVtcHRTdGF0c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2F0dGVtcHRfc3RhdHNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRBdHRlbXB0c3RhdHMocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRfc3RhdHNEb21haW4uYnVsa1JlYWRBdHRlbXB0c3RhdHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRBdHRlbXB0c3RhdHMyKHBhcmFtczogWC5CdWxrUmVhZEF0dGVtcHRzdGF0c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdF9zdGF0c0RvbWFpbi5idWxrUmVhZEF0dGVtcHRzdGF0czIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBjcmVhdGVBdHRlbXB0c3RhdChib2R5OiBYLkNyZWF0ZUF0dGVtcHRzdGF0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0c3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRfc3RhdHNEb21haW4uY3JlYXRlQXR0ZW1wdHN0YXQoYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdChib2R5OiBYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0X3N0YXRzRG9tYWluLmNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXQoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQXR0ZW1wdHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hdHRlbXB0c0RvbWFpbjogWC5BdHRlbXB0c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGF0dGVtcHRzRG9tYWluKCk6IFguQXR0ZW1wdHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2F0dGVtcHRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hdHRlbXB0c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQXR0ZW1wdHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hdHRlbXB0c0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEF0dGVtcHRzQnlDYXJkcyhjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0c0RvbWFpbi5idWxrUmVhZEF0dGVtcHRzQnlDYXJkcyhjYXJkSWQpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEF0dGVtcHRzQnlDYXJkczIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRzRG9tYWluLmJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzMihjYXJkSWQpO1xuICAgIH1cblxuICAgIGNyZWF0ZUF0dGVtcHQoYm9keTogWC5DcmVhdGVBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdHNEb21haW4uY3JlYXRlQXR0ZW1wdChib2R5KTtcbiAgICB9XG5cbiAgICB1cGRhdGVBdHRlbXB0KGF0dGVtcHRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0c0RvbWFpbi51cGRhdGVBdHRlbXB0KGF0dGVtcHRJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQXV0aCBUb2tlbnMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hdXRoX3Rva2Vuc0RvbWFpbjogWC5BdXRoVG9rZW5zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYXV0aF90b2tlbnNEb21haW4oKTogWC5BdXRoVG9rZW5zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9hdXRoX3Rva2Vuc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fYXV0aF90b2tlbnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkF1dGhUb2tlbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9hdXRoX3Rva2Vuc0RvbWFpbjtcbiAgICB9XG5cbiAgICBhdXRob3JpemVBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLkF1dGhvcml6ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmF1dGhvcml6ZUF1dGhUb2tlbigpO1xuICAgIH1cblxuICAgIGNyZWF0ZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi5jcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVHb29nbGVCYXNlZE1vYmlsZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZUF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4udXBkYXRlQXV0aFRva2VuKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2FyZHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9jYXJkc0RvbWFpbjogWC5DYXJkc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGNhcmRzRG9tYWluKCk6IFguQ2FyZHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2NhcmRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9jYXJkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQ2FyZHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9jYXJkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrRGVsZXRlQ2FyZHMocGFyYW1zOiBYLkJ1bGtEZWxldGVDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtEZWxldGVDYXJkc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLmJ1bGtEZWxldGVDYXJkcyhwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkQ2FyZHMocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLmJ1bGtSZWFkQ2FyZHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRDYXJkczIocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5idWxrUmVhZENhcmRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUNhcmQoYm9keTogWC5DcmVhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4uY3JlYXRlQ2FyZChib2R5KTtcbiAgICB9XG5cbiAgICByZWFkQ2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4ucmVhZENhcmQoY2FyZElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZENhcmQyKGNhcmRJZDogYW55LCBwYXJhbXM/OiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5yZWFkQ2FyZDIoY2FyZElkLCBwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkR2VvbWV0cmllc09ubHkyKHBhcmFtczogYW55KTogT2JzZXJ2YWJsZTxhbnk+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4uYnVsa1JlYWRHZW9tZXRyaWVzT25seTIocGFyYW1zKTtcbiAgICB9XG5cbiAgICB1cGRhdGVDYXJkKGNhcmRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi51cGRhdGVDYXJkKGNhcmRJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2F0ZWdvcmllcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2NhdGVnb3JpZXNEb21haW46IFguQ2F0ZWdvcmllc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGNhdGVnb3JpZXNEb21haW4oKTogWC5DYXRlZ29yaWVzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9jYXRlZ29yaWVzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9jYXRlZ29yaWVzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5DYXRlZ29yaWVzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fY2F0ZWdvcmllc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZENhdGVnb3JpZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXRlZ29yaWVzRG9tYWluLmJ1bGtSZWFkQ2F0ZWdvcmllcygpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZENhdGVnb3JpZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhdGVnb3JpZXNEb21haW4uYnVsa1JlYWRDYXRlZ29yaWVzMigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENvbnRhY3QgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9jb250YWN0c0RvbWFpbjogWC5Db250YWN0c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGNvbnRhY3RzRG9tYWluKCk6IFguQ29udGFjdHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2NvbnRhY3RzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9jb250YWN0c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQ29udGFjdHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9jb250YWN0c0RvbWFpbjtcbiAgICB9XG5cbiAgICBjcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLkNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbnRhY3RzRG9tYWluLmNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHkpO1xuICAgIH1cblxuICAgIHNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2UoYm9keTogWC5TZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlQm9keSk6IE9ic2VydmFibGU8WC5TZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29udGFjdHNEb21haW4uc2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZShib2R5KTtcbiAgICB9XG5cbiAgICB2ZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdChib2R5OiBYLlZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5WZXJpZnlBbm9ueW1vdXNDb250YWN0QXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbnRhY3RzRG9tYWluLnZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIERvbmF0aW9ucyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2RvbmF0aW9uc0RvbWFpbjogWC5Eb25hdGlvbnNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBkb25hdGlvbnNEb21haW4oKTogWC5Eb25hdGlvbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2RvbmF0aW9uc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZG9uYXRpb25zRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Eb25hdGlvbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9kb25hdGlvbnNEb21haW47XG4gICAgfVxuXG4gICAgY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbihwYXJhbXM6IFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5KTogRGF0YVN0YXRlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmRvbmF0aW9uc0RvbWFpbi5jaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb24yKHBhcmFtczogWC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnkpOiBPYnNlcnZhYmxlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmRvbmF0aW9uc0RvbWFpbi5jaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUFub255bW91c0RvbmF0aW9uKGJvZHk6IFguQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNyZWF0ZUFub255bW91c0RvbmF0aW9uKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZURvbmF0aW9uKGJvZHk6IFguQ3JlYXRlRG9uYXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNyZWF0ZURvbmF0aW9uKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZURvbmF0aW9uYXR0ZW1wdChib2R5OiBYLkNyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNyZWF0ZURvbmF0aW9uYXR0ZW1wdChib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBFeHRlcm5hbCBBcHBzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZXh0ZXJuYWxfYXBwc0RvbWFpbjogWC5FeHRlcm5hbEFwcHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBleHRlcm5hbF9hcHBzRG9tYWluKCk6IFguRXh0ZXJuYWxBcHBzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9leHRlcm5hbF9hcHBzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9leHRlcm5hbF9hcHBzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5FeHRlcm5hbEFwcHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9leHRlcm5hbF9hcHBzRG9tYWluO1xuICAgIH1cblxuICAgIGF1dGhvcml6ZUV4dGVybmFsQXBwQXV0aFRva2VuKCk6IE9ic2VydmFibGU8WC5BdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmV4dGVybmFsX2FwcHNEb21haW4uYXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW4oKTtcbiAgICB9XG5cbiAgICBjcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmV4dGVybmFsX2FwcHNEb21haW4uY3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZEV4dGVybmFsYXBwY29uZihwYXJhbXM6IFguUmVhZEV4dGVybmFsYXBwY29uZlF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmV4dGVybmFsX2FwcHNEb21haW4ucmVhZEV4dGVybmFsYXBwY29uZihwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICByZWFkRXh0ZXJuYWxhcHBjb25mMihwYXJhbXM6IFguUmVhZEV4dGVybmFsYXBwY29uZlF1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5leHRlcm5hbF9hcHBzRG9tYWluLnJlYWRFeHRlcm5hbGFwcGNvbmYyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRm9jdXMgUmVjb3JkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ZvY3VzX3JlY29yZHNEb21haW46IFguRm9jdXNSZWNvcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZm9jdXNfcmVjb3Jkc0RvbWFpbigpOiBYLkZvY3VzUmVjb3Jkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZm9jdXNfcmVjb3Jkc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZm9jdXNfcmVjb3Jkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRm9jdXNSZWNvcmRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZm9jdXNfcmVjb3Jkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBjcmVhdGVGb2N1c3JlY29yZChib2R5OiBYLkNyZWF0ZUZvY3VzcmVjb3JkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGb2N1c3JlY29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZvY3VzX3JlY29yZHNEb21haW4uY3JlYXRlRm9jdXNyZWNvcmQoYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZEZvY3VzUmVjb3JkU3VtbWFyeSgpOiBEYXRhU3RhdGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZm9jdXNfcmVjb3Jkc0RvbWFpbi5yZWFkRm9jdXNSZWNvcmRTdW1tYXJ5KCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRGb2N1c1JlY29yZFN1bW1hcnkyKCk6IE9ic2VydmFibGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZm9jdXNfcmVjb3Jkc0RvbWFpbi5yZWFkRm9jdXNSZWNvcmRTdW1tYXJ5MigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEZyYWdtZW50IEhhc2h0YWdzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZnJhZ21lbnRfaGFzaHRhZ3NEb21haW46IFguRnJhZ21lbnRIYXNodGFnc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGZyYWdtZW50X2hhc2h0YWdzRG9tYWluKCk6IFguRnJhZ21lbnRIYXNodGFnc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ZyYWdtZW50X2hhc2h0YWdzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5GcmFnbWVudEhhc2h0YWdzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZnJhZ21lbnRfaGFzaHRhZ3NEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X2hhc2h0YWdzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFncyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X2hhc2h0YWdzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBGcmFnbWVudCBXb3JkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ZyYWdtZW50X3dvcmRzRG9tYWluOiBYLkZyYWdtZW50V29yZHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBmcmFnbWVudF93b3Jkc0RvbWFpbigpOiBYLkZyYWdtZW50V29yZHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2ZyYWdtZW50X3dvcmRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9mcmFnbWVudF93b3Jkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRnJhZ21lbnRXb3Jkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ZyYWdtZW50X3dvcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X3dvcmRzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRXb3JkcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEZyYWdtZW50V29yZHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50V29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X3dvcmRzRG9tYWluLmJ1bGtSZWFkRnJhZ21lbnRXb3JkczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF93b3Jkc0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF93b3Jkc0RvbWFpbi5idWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRnJhZ21lbnRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZnJhZ21lbnRzRG9tYWluOiBYLkZyYWdtZW50c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGZyYWdtZW50c0RvbWFpbigpOiBYLkZyYWdtZW50c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZnJhZ21lbnRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9mcmFnbWVudHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkZyYWdtZW50c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ZyYWdtZW50c0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEZyYWdtZW50cyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uYnVsa1JlYWRGcmFnbWVudHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uYnVsa1JlYWRGcmFnbWVudHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUZyYWdtZW50KCk6IE9ic2VydmFibGU8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5jcmVhdGVGcmFnbWVudCgpO1xuICAgIH1cblxuICAgIGRlbGV0ZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5kZWxldGVGcmFnbWVudChmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICBtZXJnZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5NZXJnZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLm1lcmdlRnJhZ21lbnQoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgcHVibGlzaEZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5QdWJsaXNoRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucHVibGlzaEZyYWdtZW50KGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIHJlYWRGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50KGZyYWdtZW50SWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkRnJhZ21lbnQyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50MihmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICByZWFkRnJhZ21lbnREaWZmKGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50RGlmZihmcmFnbWVudElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEZyYWdtZW50RGlmZjIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ucmVhZEZyYWdtZW50RGlmZjIoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgcmVhZEZyYWdtZW50U2FtcGxlKGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnRTYW1wbGUoZnJhZ21lbnRJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRGcmFnbWVudFNhbXBsZTIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnRTYW1wbGUyKGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIHVwZGF0ZUZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSwgYm9keTogWC5VcGRhdGVGcmFnbWVudEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4udXBkYXRlRnJhZ21lbnQoZnJhZ21lbnRJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogR2VvbWV0cmllcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2dlb21ldHJpZXNEb21haW46IFguR2VvbWV0cmllc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGdlb21ldHJpZXNEb21haW4oKTogWC5HZW9tZXRyaWVzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9nZW9tZXRyaWVzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9nZW9tZXRyaWVzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5HZW9tZXRyaWVzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZ2VvbWV0cmllc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEdlb21ldHJpZXMocGFyYW1zOiBYLkJ1bGtSZWFkR2VvbWV0cmllc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLmJ1bGtSZWFkR2VvbWV0cmllcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEdlb21ldHJpZXMyKHBhcmFtczogWC5CdWxrUmVhZEdlb21ldHJpZXNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEdlb21ldHJpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4uYnVsa1JlYWRHZW9tZXRyaWVzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtVcGRhdGVHZW9tZXRyaWVzKGJvZHk6IFguQnVsa1VwZGF0ZUdlb21ldHJpZXNCb2R5KTogT2JzZXJ2YWJsZTxYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5idWxrVXBkYXRlR2VvbWV0cmllcyhib2R5KTtcbiAgICB9XG5cbiAgICByZWFkR2VvbWV0cnlCeUNhcmQoY2FyZElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLnJlYWRHZW9tZXRyeUJ5Q2FyZChjYXJkSWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkR2VvbWV0cnlCeUNhcmQyKGNhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4ucmVhZEdlb21ldHJ5QnlDYXJkMihjYXJkSWQpO1xuICAgIH1cblxuICAgIHJlYWRHcmFwaChwYXJhbXM6IFguUmVhZEdyYXBoUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkR3JhcGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLnJlYWRHcmFwaChwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICByZWFkR3JhcGgyKHBhcmFtczogWC5SZWFkR3JhcGhRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkR3JhcGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLnJlYWRHcmFwaDIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBIYXNodGFncyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2hhc2h0YWdzRG9tYWluOiBYLkhhc2h0YWdzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgaGFzaHRhZ3NEb21haW4oKTogWC5IYXNodGFnc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5faGFzaHRhZ3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2hhc2h0YWdzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5IYXNodGFnc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2hhc2h0YWdzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkSGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLmJ1bGtSZWFkSGFzaHRhZ3MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5idWxrUmVhZEhhc2h0YWdzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUhhc2h0YWcoYm9keTogWC5DcmVhdGVIYXNodGFnQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVIYXNodGFnUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4uY3JlYXRlSGFzaHRhZyhib2R5KTtcbiAgICB9XG5cbiAgICBkZWxldGVIYXNodGFnKGhhc2h0YWdJZDogYW55LCBwYXJhbXM6IFguRGVsZXRlSGFzaHRhZ1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5kZWxldGVIYXNodGFnKGhhc2h0YWdJZCwgcGFyYW1zKTtcbiAgICB9XG5cbiAgICByZWFkSGFzaHRhZ3NUb2MocGFyYW1zOiBYLlJlYWRIYXNodGFnc1RvY1F1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4ucmVhZEhhc2h0YWdzVG9jKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRIYXNodGFnc1RvYzIocGFyYW1zOiBYLlJlYWRIYXNodGFnc1RvY1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLnJlYWRIYXNodGFnc1RvYzIocGFyYW1zKTtcbiAgICB9XG5cbiAgICB1cGRhdGVIYXNodGFnKGhhc2h0YWdJZDogYW55LCBib2R5OiBYLlVwZGF0ZUhhc2h0YWdCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi51cGRhdGVIYXNodGFnKGhhc2h0YWdJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogSW50ZXJuYWwgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9pbnRlcm5hbERvbWFpbjogWC5JbnRlcm5hbERvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGludGVybmFsRG9tYWluKCk6IFguSW50ZXJuYWxEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2ludGVybmFsRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9pbnRlcm5hbERvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguSW50ZXJuYWxEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9pbnRlcm5hbERvbWFpbjtcbiAgICB9XG5cbiAgICBkZWxldGVFbnRyaWVzRm9yVXNlcih1c2VySWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVFbnRyaWVzRm9yVXNlclJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmludGVybmFsRG9tYWluLmRlbGV0ZUVudHJpZXNGb3JVc2VyKHVzZXJJZCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogSW52b2ljZSBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ludm9pY2VzRG9tYWluOiBYLkludm9pY2VzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgaW52b2ljZXNEb21haW4oKTogWC5JbnZvaWNlc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5faW52b2ljZXNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ludm9pY2VzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5JbnZvaWNlc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ludm9pY2VzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkSW52b2ljZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaW52b2ljZXNEb21haW4uYnVsa1JlYWRJbnZvaWNlcygpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEludm9pY2VzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaW52b2ljZXNEb21haW4uYnVsa1JlYWRJbnZvaWNlczIoKTtcbiAgICB9XG5cbiAgICBjYWxjdWxhdGVEZWJ0KCk6IERhdGFTdGF0ZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5jYWxjdWxhdGVEZWJ0KCk7XG4gICAgfVxuICAgIFxuICAgIGNhbGN1bGF0ZURlYnQyKCk6IE9ic2VydmFibGU8WC5DYWxjdWxhdGVEZWJ0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaW52b2ljZXNEb21haW4uY2FsY3VsYXRlRGVidDIoKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaW5rcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2xpbmtzRG9tYWluOiBYLkxpbmtzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgbGlua3NEb21haW4oKTogWC5MaW5rc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fbGlua3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2xpbmtzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5MaW5rc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2xpbmtzRG9tYWluO1xuICAgIH1cblxuICAgIGRlbGV0ZUxpbmsoZnJvbUNhcmRJZDogYW55LCB0b0NhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUxpbmtSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5saW5rc0RvbWFpbi5kZWxldGVMaW5rKGZyb21DYXJkSWQsIHRvQ2FyZElkKTtcbiAgICB9XG5cbiAgICByZWFkT3JDcmVhdGVMaW5rKGJvZHk6IFguUmVhZE9yQ3JlYXRlTGlua0JvZHkpOiBPYnNlcnZhYmxlPFguUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmxpbmtzRG9tYWluLnJlYWRPckNyZWF0ZUxpbmsoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTWVkaWFJdGVtcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX21lZGlhaXRlbXNEb21haW46IFguTWVkaWFpdGVtc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IG1lZGlhaXRlbXNEb21haW4oKTogWC5NZWRpYWl0ZW1zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9tZWRpYWl0ZW1zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9tZWRpYWl0ZW1zRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5NZWRpYWl0ZW1zRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fbWVkaWFpdGVtc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZE1lZGlhaXRlbXMocGFyYW1zOiBYLkJ1bGtSZWFkTWVkaWFpdGVtc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLmJ1bGtSZWFkTWVkaWFpdGVtcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZE1lZGlhaXRlbXMyKHBhcmFtczogWC5CdWxrUmVhZE1lZGlhaXRlbXNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4uYnVsa1JlYWRNZWRpYWl0ZW1zMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGRlbGV0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55LCBwYXJhbXM6IFguRGVsZXRlTWVkaWFpdGVtUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5kZWxldGVNZWRpYWl0ZW0obWVkaWFpdGVtSWQsIHBhcmFtcyk7XG4gICAgfVxuXG4gICAgcmVhZE1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55KTogRGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE1lZGlhaXRlbShtZWRpYWl0ZW1JZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRNZWRpYWl0ZW0yKG1lZGlhaXRlbUlkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE1lZGlhaXRlbTIobWVkaWFpdGVtSWQpO1xuICAgIH1cblxuICAgIHJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZChwcm9jZXNzSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkKHByb2Nlc3NJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZDIocHJvY2Vzc0lkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5yZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWQyKHByb2Nlc3NJZCk7XG4gICAgfVxuXG4gICAgcmVhZE9yQ3JlYXRlTWVkaWFpdGVtKGJvZHk6IFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtQm9keSk6IE9ic2VydmFibGU8WC5SZWFkT3JDcmVhdGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLnJlYWRPckNyZWF0ZU1lZGlhaXRlbShib2R5KTtcbiAgICB9XG5cbiAgICB1cGRhdGVNZWRpYWl0ZW0obWVkaWFpdGVtSWQ6IGFueSwgYm9keTogWC5VcGRhdGVNZWRpYWl0ZW1Cb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZU1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4udXBkYXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkLCBib2R5KTtcbiAgICB9XG5cbiAgICB1cGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvbihtZWRpYWl0ZW1JZDogYW55LCBib2R5OiBYLlVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4udXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb24obWVkaWFpdGVtSWQsIGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIE5vdGlmaWNhdGlvbiBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX25vdGlmaWNhdGlvbnNEb21haW46IFguTm90aWZpY2F0aW9uc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IG5vdGlmaWNhdGlvbnNEb21haW4oKTogWC5Ob3RpZmljYXRpb25zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9ub3RpZmljYXRpb25zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9ub3RpZmljYXRpb25zRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Ob3RpZmljYXRpb25zRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fbm90aWZpY2F0aW9uc0RvbWFpbjtcbiAgICB9XG5cbiAgICBhY2tub3dsZWRnZU5vdGlmaWNhdGlvbihub3RpZmljYXRpb25JZDogYW55KTogT2JzZXJ2YWJsZTxYLkFja25vd2xlZGdlTm90aWZpY2F0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubm90aWZpY2F0aW9uc0RvbWFpbi5hY2tub3dsZWRnZU5vdGlmaWNhdGlvbihub3RpZmljYXRpb25JZCk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWROb3RpZmljYXRpb25zKHBhcmFtczogWC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubm90aWZpY2F0aW9uc0RvbWFpbi5idWxrUmVhZE5vdGlmaWNhdGlvbnMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWROb3RpZmljYXRpb25zMihwYXJhbXM6IFguQnVsa1JlYWROb3RpZmljYXRpb25zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5ub3RpZmljYXRpb25zRG9tYWluLmJ1bGtSZWFkTm90aWZpY2F0aW9uczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQYXRocyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3BhdGhzRG9tYWluOiBYLlBhdGhzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcGF0aHNEb21haW4oKTogWC5QYXRoc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcGF0aHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3BhdGhzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5QYXRoc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3BhdGhzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtEZWxldGVQYXRocyhwYXJhbXM6IFguQnVsa0RlbGV0ZVBhdGhzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa0RlbGV0ZVBhdGhzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4uYnVsa0RlbGV0ZVBhdGhzKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRQYXRocyhwYXJhbXM6IFguQnVsa1JlYWRQYXRoc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4uYnVsa1JlYWRQYXRocyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFBhdGhzMihwYXJhbXM6IFguQnVsa1JlYWRQYXRoc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLmJ1bGtSZWFkUGF0aHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlUGF0aChib2R5OiBYLkNyZWF0ZVBhdGhCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5jcmVhdGVQYXRoKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRQYXRoKHBhdGhJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZFBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5yZWFkUGF0aChwYXRoSWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkUGF0aDIocGF0aElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZFBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5yZWFkUGF0aDIocGF0aElkKTtcbiAgICB9XG5cbiAgICB1cGRhdGVQYXRoKHBhdGhJZDogYW55LCBib2R5OiBYLlVwZGF0ZVBhdGhCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVBhdGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi51cGRhdGVQYXRoKHBhdGhJZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUGF5bWVudCBDYXJkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3BheW1lbnRfY2FyZHNEb21haW46IFguUGF5bWVudENhcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgcGF5bWVudF9jYXJkc0RvbWFpbigpOiBYLlBheW1lbnRDYXJkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcGF5bWVudF9jYXJkc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcGF5bWVudF9jYXJkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguUGF5bWVudENhcmRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fcGF5bWVudF9jYXJkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBhc0RlZmF1bHRNYXJrUGF5bWVudGNhcmQocGF5bWVudENhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uYXNEZWZhdWx0TWFya1BheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUGF5bWVudGNhcmRzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLmJ1bGtSZWFkUGF5bWVudGNhcmRzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUGF5bWVudGNhcmRzMigpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uYnVsa1JlYWRQYXltZW50Y2FyZHMyKCk7XG4gICAgfVxuXG4gICAgY3JlYXRlUGF5bWVudGNhcmQoYm9keTogWC5DcmVhdGVQYXltZW50Y2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLmNyZWF0ZVBheW1lbnRjYXJkKGJvZHkpO1xuICAgIH1cblxuICAgIGRlbGV0ZVBheW1lbnRjYXJkKHBheW1lbnRDYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5EZWxldGVQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uZGVsZXRlUGF5bWVudGNhcmQocGF5bWVudENhcmRJZCk7XG4gICAgfVxuXG4gICAgcGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZChib2R5OiBYLlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLnBheVdpdGhEZWZhdWx0UGF5bWVudENhcmQoYm9keSk7XG4gICAgfVxuXG4gICAgcmVuZGVyUGF5bWVudENhcmRXaWRnZXQoKTogRGF0YVN0YXRlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLnJlbmRlclBheW1lbnRDYXJkV2lkZ2V0KCk7XG4gICAgfVxuICAgIFxuICAgIHJlbmRlclBheW1lbnRDYXJkV2lkZ2V0MigpOiBPYnNlcnZhYmxlPFguUmVuZGVyUGF5bWVudENhcmRXaWRnZXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50X2NhcmRzRG9tYWluLnJlbmRlclBheW1lbnRDYXJkV2lkZ2V0MigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBheW1lbnRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfcGF5bWVudHNEb21haW46IFguUGF5bWVudHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBwYXltZW50c0RvbWFpbigpOiBYLlBheW1lbnRzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wYXltZW50c0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcGF5bWVudHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlBheW1lbnRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fcGF5bWVudHNEb21haW47XG4gICAgfVxuXG4gICAgdXBkYXRlUGF5bWVudFN0YXR1cyhib2R5OiBYLlVwZGF0ZVBheW1lbnRTdGF0dXNCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZVBheW1lbnRTdGF0dXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXltZW50c0RvbWFpbi51cGRhdGVQYXltZW50U3RhdHVzKGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlY2FsbCBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3JlY2FsbERvbWFpbjogWC5SZWNhbGxEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCByZWNhbGxEb21haW4oKTogWC5SZWNhbGxEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3JlY2FsbERvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcmVjYWxsRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5SZWNhbGxEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9yZWNhbGxEb21haW47XG4gICAgfVxuXG4gICAgY3JlYXRlUmVjYWxsU2Vzc2lvbihib2R5OiBYLkNyZWF0ZVJlY2FsbFNlc3Npb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVJlY2FsbFNlc3Npb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5yZWNhbGxEb21haW4uY3JlYXRlUmVjYWxsU2Vzc2lvbihib2R5KTtcbiAgICB9XG5cbiAgICByZWFkUmVjYWxsU3VtbWFyeSgpOiBEYXRhU3RhdGU8WC5SZWFkUmVjYWxsU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnJlY2FsbERvbWFpbi5yZWFkUmVjYWxsU3VtbWFyeSgpO1xuICAgIH1cbiAgICBcbiAgICByZWFkUmVjYWxsU3VtbWFyeTIoKTogT2JzZXJ2YWJsZTxYLlJlYWRSZWNhbGxTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucmVjYWxsRG9tYWluLnJlYWRSZWNhbGxTdW1tYXJ5MigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFN1YnNjcmlwdGlvbiBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3N1YnNjcmlwdGlvbnNEb21haW46IFguU3Vic2NyaXB0aW9uc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHN1YnNjcmlwdGlvbnNEb21haW4oKTogWC5TdWJzY3JpcHRpb25zRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9zdWJzY3JpcHRpb25zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9zdWJzY3JpcHRpb25zRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5TdWJzY3JpcHRpb25zRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fc3Vic2NyaXB0aW9uc0RvbWFpbjtcbiAgICB9XG5cbiAgICBjaGFuZ2VTdWJzY3JpcHRpb24oYm9keTogWC5DaGFuZ2VTdWJzY3JpcHRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNoYW5nZVN1YnNjcmlwdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnN1YnNjcmlwdGlvbnNEb21haW4uY2hhbmdlU3Vic2NyaXB0aW9uKGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFRhc2tzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfdGFza3NEb21haW46IFguVGFza3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCB0YXNrc0RvbWFpbigpOiBYLlRhc2tzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl90YXNrc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fdGFza3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlRhc2tzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fdGFza3NEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRUYXNrcyhwYXJhbXM6IFguQnVsa1JlYWRUYXNrc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMudGFza3NEb21haW4uYnVsa1JlYWRUYXNrcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFRhc2tzMihwYXJhbXM6IFguQnVsa1JlYWRUYXNrc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnRhc2tzRG9tYWluLmJ1bGtSZWFkVGFza3MyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRUYXNrQmlucyhwYXJhbXM6IFguQnVsa1JlYWRUYXNrQmluc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMudGFza3NEb21haW4uYnVsa1JlYWRUYXNrQmlucyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFRhc2tCaW5zMihwYXJhbXM6IFguQnVsa1JlYWRUYXNrQmluc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnRhc2tzRG9tYWluLmJ1bGtSZWFkVGFza0JpbnMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogV29yZHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF93b3Jkc0RvbWFpbjogWC5Xb3Jkc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHdvcmRzRG9tYWluKCk6IFguV29yZHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3dvcmRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl93b3Jkc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguV29yZHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl93b3Jkc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZFdvcmRzKHBhcmFtczogWC5CdWxrUmVhZFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy53b3Jkc0RvbWFpbi5idWxrUmVhZFdvcmRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkV29yZHMyKHBhcmFtczogWC5CdWxrUmVhZFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMud29yZHNEb21haW4uYnVsa1JlYWRXb3JkczIocGFyYW1zKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG5pbXBvcnQgeyBOZ01vZHVsZSwgTW9kdWxlV2l0aFByb3ZpZGVycyB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgSHR0cENsaWVudE1vZHVsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcblxuLyoqIERvbWFpbnMgKi9cbmltcG9ydCB7IEFjY291bnRTZXR0aW5nc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9hY2NvdW50X3NldHRpbmdzL2luZGV4JztcbmltcG9ydCB7IEFjY291bnRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2FjY291bnRzL2luZGV4JztcbmltcG9ydCB7IEF0dGVtcHRTdGF0c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9hdHRlbXB0X3N0YXRzL2luZGV4JztcbmltcG9ydCB7IEF0dGVtcHRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2F0dGVtcHRzL2luZGV4JztcbmltcG9ydCB7IEF1dGhUb2tlbnNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvYXV0aF90b2tlbnMvaW5kZXgnO1xuaW1wb3J0IHsgQ2FyZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvY2FyZHMvaW5kZXgnO1xuaW1wb3J0IHsgQ2F0ZWdvcmllc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9jYXRlZ29yaWVzL2luZGV4JztcbmltcG9ydCB7IENvbnRhY3RzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2NvbnRhY3RzL2luZGV4JztcbmltcG9ydCB7IERvbmF0aW9uc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9kb25hdGlvbnMvaW5kZXgnO1xuaW1wb3J0IHsgRXh0ZXJuYWxBcHBzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2V4dGVybmFsX2FwcHMvaW5kZXgnO1xuaW1wb3J0IHsgRm9jdXNSZWNvcmRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZvY3VzX3JlY29yZHMvaW5kZXgnO1xuaW1wb3J0IHsgRnJhZ21lbnRIYXNodGFnc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9mcmFnbWVudF9oYXNodGFncy9pbmRleCc7XG5pbXBvcnQgeyBGcmFnbWVudFdvcmRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZyYWdtZW50X3dvcmRzL2luZGV4JztcbmltcG9ydCB7IEZyYWdtZW50c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9mcmFnbWVudHMvaW5kZXgnO1xuaW1wb3J0IHsgR2VvbWV0cmllc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9nZW9tZXRyaWVzL2luZGV4JztcbmltcG9ydCB7IEhhc2h0YWdzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2hhc2h0YWdzL2luZGV4JztcbmltcG9ydCB7IEludGVybmFsRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ludGVybmFsL2luZGV4JztcbmltcG9ydCB7IEludm9pY2VzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ludm9pY2VzL2luZGV4JztcbmltcG9ydCB7IExpbmtzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2xpbmtzL2luZGV4JztcbmltcG9ydCB7IE1lZGlhaXRlbXNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvbWVkaWFpdGVtcy9pbmRleCc7XG5pbXBvcnQgeyBOb3RpZmljYXRpb25zRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL25vdGlmaWNhdGlvbnMvaW5kZXgnO1xuaW1wb3J0IHsgUGF0aHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcGF0aHMvaW5kZXgnO1xuaW1wb3J0IHsgUGF5bWVudENhcmRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL3BheW1lbnRfY2FyZHMvaW5kZXgnO1xuaW1wb3J0IHsgUGF5bWVudHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcGF5bWVudHMvaW5kZXgnO1xuaW1wb3J0IHsgUmVjYWxsRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL3JlY2FsbC9pbmRleCc7XG5pbXBvcnQgeyBTdWJzY3JpcHRpb25zRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL3N1YnNjcmlwdGlvbnMvaW5kZXgnO1xuaW1wb3J0IHsgVGFza3NEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvdGFza3MvaW5kZXgnO1xuaW1wb3J0IHsgV29yZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvd29yZHMvaW5kZXgnO1xuXG4vKiogU2VydmljZXMgKi9cbi8vIGltcG9ydCB7XG4vLyAgIEFQSVNlcnZpY2UsXG4vLyAgIENsaWVudFNlcnZpY2UsXG4vLyAgIC8vIENvbmZpZ1NlcnZpY2UsXG4vLyAgIENvbmZpZ1xuLy8gfSBmcm9tICcuL3NlcnZpY2VzL2luZGV4JztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgQVBJU2VydmljZSB9IGZyb20gJy4vc2VydmljZXMvYXBpLnNlcnZpY2UnO1xuaW1wb3J0IHsgQ29uZmlnIH0gZnJvbSAnLi9zZXJ2aWNlcy9jb25maWcuc2VydmljZSc7XG5cblxuLy8gZXhwb3J0IGZ1bmN0aW9uIGNvbmZpZ0ZhY3RvcnkoY29uZmlnOiBDb25maWcpIHtcbi8vICAgcmV0dXJuIG5ldyBDb25maWdTZXJ2aWNlKGNvbmZpZyk7XG4vLyB9XG5cbkBOZ01vZHVsZSh7XG4gIGltcG9ydHM6IFtIdHRwQ2xpZW50TW9kdWxlXSxcbiAgcHJvdmlkZXJzOiBbXG4gICAgQ2xpZW50U2VydmljZSxcblxuICAgIC8vIERvbWFpbnNcbiAgICBBY2NvdW50U2V0dGluZ3NEb21haW4sXG4gICAgQWNjb3VudHNEb21haW4sXG4gICAgQXR0ZW1wdFN0YXRzRG9tYWluLFxuICAgIEF0dGVtcHRzRG9tYWluLFxuICAgIEF1dGhUb2tlbnNEb21haW4sXG4gICAgQ2FyZHNEb21haW4sXG4gICAgQ2F0ZWdvcmllc0RvbWFpbixcbiAgICBDb250YWN0c0RvbWFpbixcbiAgICBEb25hdGlvbnNEb21haW4sXG4gICAgRXh0ZXJuYWxBcHBzRG9tYWluLFxuICAgIEZvY3VzUmVjb3Jkc0RvbWFpbixcbiAgICBGcmFnbWVudEhhc2h0YWdzRG9tYWluLFxuICAgIEZyYWdtZW50V29yZHNEb21haW4sXG4gICAgRnJhZ21lbnRzRG9tYWluLFxuICAgIEdlb21ldHJpZXNEb21haW4sXG4gICAgSGFzaHRhZ3NEb21haW4sXG4gICAgSW50ZXJuYWxEb21haW4sXG4gICAgSW52b2ljZXNEb21haW4sXG4gICAgTGlua3NEb21haW4sXG4gICAgTWVkaWFpdGVtc0RvbWFpbixcbiAgICBOb3RpZmljYXRpb25zRG9tYWluLFxuICAgIFBhdGhzRG9tYWluLFxuICAgIFBheW1lbnRDYXJkc0RvbWFpbixcbiAgICBQYXltZW50c0RvbWFpbixcbiAgICBSZWNhbGxEb21haW4sXG4gICAgU3Vic2NyaXB0aW9uc0RvbWFpbixcbiAgICBUYXNrc0RvbWFpbixcbiAgICBXb3Jkc0RvbWFpbixcblxuICAgIC8vIEZhY2FkZVxuICAgIEFQSVNlcnZpY2UsXG4gIF1cbn0pXG5leHBvcnQgY2xhc3MgQ2xpZW50TW9kdWxlIHtcbiAgICBzdGF0aWMgZm9yUm9vdChjb25maWc6IENvbmZpZyk6IE1vZHVsZVdpdGhQcm92aWRlcnMge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgbmdNb2R1bGU6IENsaWVudE1vZHVsZSxcbiAgICAgICAgICAgIHByb3ZpZGVyczogW1xuICAgICAgICAgICAgICAgIC8vIHtcbiAgICAgICAgICAgICAgICAvLyAgICAgcHJvdmlkZTogQ29uZmlnU2VydmljZSxcbiAgICAgICAgICAgICAgICAvLyAgICAgdXNlRmFjdG9yeTogY29uZmlnRmFjdG9yeShjb25maWcpXG4gICAgICAgICAgICAgICAgLy8gfSwsXG4gICAgICAgICAgICAgICAge3Byb3ZpZGU6ICdjb25maWcnLCB1c2VWYWx1ZTogY29uZmlnfVxuICAgICAgICAgICAgXVxuICAgICAgICB9O1xuICAgIH1cbn0iLCIvKipcbiAqIEdlbmVyYXRlZCBidW5kbGUgaW5kZXguIERvIG5vdCBlZGl0LlxuICovXG5cbmV4cG9ydCAqIGZyb20gJy4vcHVibGljX2FwaSc7XG5cbmV4cG9ydCB7Q29uZmlnIGFzIMOJwrVhfSBmcm9tICcuL3NlcnZpY2VzL2NvbmZpZy5zZXJ2aWNlJzsiXSwibmFtZXMiOlsicmV0cnkiLCJjYXRjaEVycm9yIiwiXy5oYXMiLCJtYXAiLCJfLmlzRW1wdHkiLCJCZWhhdmlvclN1YmplY3QiLCJ0aHJvd0Vycm9yIiwiSW5qZWN0YWJsZSIsIkluamVjdCIsIkh0dHBDbGllbnQiLCJmaWx0ZXIiLCJCdWxrUmVhZEFjY291bnRzUmVzcG9uc2VBdHlwZSIsIlJlYWRBY2NvdW50UmVzcG9uc2VBdHlwZSIsIlVwZGF0ZUFjY291bnRSZXNwb25zZUF0eXBlIiwiQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VUZXh0IiwiQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblF1ZXJ5RXZlbnQiLCJDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlQ3VycmVuY3kiLCJDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGUiLCJDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlU3RhdHVzIiwiQ3JlYXRlRG9uYXRpb25SZXNwb25zZUN1cnJlbmN5IiwiQ3JlYXRlRG9uYXRpb25SZXNwb25zZVByb2R1Y3RUeXBlIiwiQ3JlYXRlRG9uYXRpb25SZXNwb25zZVN0YXR1cyIsIkNyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHlFdmVudCIsIkNyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlRXZlbnQiLCJCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VDdXJyZW5jeSIsIkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZVByb2R1Y3RUeXBlIiwiUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlS2luZCIsIkJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlS2luZCIsIkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VDdXJyZW5jeSIsIkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VQcm9kdWN0VHlwZSIsIkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VTdGF0dXMiLCJDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlQ3VycmVuY3kiLCJDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlUHJvZHVjdFR5cGUiLCJDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlU3RhdHVzIiwiUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlQ3VycmVuY3kiLCJQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VQcm9kdWN0VHlwZSIsIlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZVN0YXR1cyIsIkNoYW5nZVN1YnNjcmlwdGlvbkJvZHlTdWJzY3JpcHRpb25UeXBlIiwiQnVsa1JlYWRUYXNrc1F1ZXJ5UXVldWVUeXBlIiwiQnVsa1JlYWRUYXNrc1Jlc3BvbnNlUXVldWVUeXBlIiwiQnVsa1JlYWRUYXNrQmluc1F1ZXJ5UXVldWVUeXBlIiwiQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlUXVldWVUeXBlIiwiWC5BY2NvdW50U2V0dGluZ3NEb21haW4iLCJYLkFjY291bnRzRG9tYWluIiwiWC5BdHRlbXB0U3RhdHNEb21haW4iLCJYLkF0dGVtcHRzRG9tYWluIiwiWC5BdXRoVG9rZW5zRG9tYWluIiwiWC5DYXJkc0RvbWFpbiIsIlguQ2F0ZWdvcmllc0RvbWFpbiIsIlguQ29udGFjdHNEb21haW4iLCJYLkRvbmF0aW9uc0RvbWFpbiIsIlguRXh0ZXJuYWxBcHBzRG9tYWluIiwiWC5Gb2N1c1JlY29yZHNEb21haW4iLCJYLkZyYWdtZW50SGFzaHRhZ3NEb21haW4iLCJYLkZyYWdtZW50V29yZHNEb21haW4iLCJYLkZyYWdtZW50c0RvbWFpbiIsIlguR2VvbWV0cmllc0RvbWFpbiIsIlguSGFzaHRhZ3NEb21haW4iLCJYLkludGVybmFsRG9tYWluIiwiWC5JbnZvaWNlc0RvbWFpbiIsIlguTGlua3NEb21haW4iLCJYLk1lZGlhaXRlbXNEb21haW4iLCJYLk5vdGlmaWNhdGlvbnNEb21haW4iLCJYLlBhdGhzRG9tYWluIiwiWC5QYXltZW50Q2FyZHNEb21haW4iLCJYLlBheW1lbnRzRG9tYWluIiwiWC5SZWNhbGxEb21haW4iLCJYLlN1YnNjcmlwdGlvbnNEb21haW4iLCJYLlRhc2tzRG9tYWluIiwiWC5Xb3Jkc0RvbWFpbiIsIkluamVjdG9yIiwiTmdNb2R1bGUiLCJIdHRwQ2xpZW50TW9kdWxlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O1FBbUNFLHVCQUFzQyxNQUFjLEVBQVUsSUFBZ0I7WUFBeEMsV0FBTSxHQUFOLE1BQU0sQ0FBUTtZQUFVLFNBQUksR0FBSixJQUFJLENBQVk7Ozs7WUFkOUUsVUFBSyxHQUFHLElBQUksR0FBRyxFQUFzQixDQUFDO1lBS3JCLHFCQUFnQixHQUFXLFlBQVksQ0FBQzs7Ozs7O1lBT3hDLGNBQVMsR0FBRyxJQUFJLEdBQUcsRUFBRSxHQUFHLEVBQUUsQ0FBQztZQUcxQyxJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO1lBQ25DLElBQUksQ0FBQyxTQUFTO2dCQUNaLElBQUksQ0FBQyxNQUFNLENBQUMsU0FBUyxJQUFJLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQztTQUNsRDtRQUVELDJCQUFHLEdBQUgsVUFBTyxRQUFnQixFQUFFLE9BQWlCO1lBQ3hDLElBQU0sR0FBRyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUM7WUFDbEMsSUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLGNBQWMsQ0FBQyxPQUFPLENBQUMsQ0FBQztZQUNqRCxPQUFPLElBQUksQ0FBQyxJQUFJO2lCQUNiLEdBQUcsQ0FBQyxHQUFHLEVBQUUsV0FBVyxDQUFDO2lCQUNyQixJQUFJLENBQUNBLGVBQUssQ0FBQyxDQUFDLENBQUMsRUFBRUMsb0JBQVUsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQWtCLENBQUM7U0FDbEU7UUFFRCw0QkFBSSxHQUFKLFVBQVEsUUFB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