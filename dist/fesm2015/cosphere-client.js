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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/account/serializers.py/#lines-23
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/account/serializers.py/#lines-8
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/account/serializers.py/#lines-8
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
        return this.client.getDataState(`/recall/attempts/by_card/${cardId}`, { responseMap: 'attempts', authorizationRequired: true });
    }
    bulkReadAttemptsByCards2(cardId) {
        return this.client.get(`/recall/attempts/by_card/${cardId}`, { responseMap: 'attempts', authorizationRequired: true });
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
        return this.client.getDataState('/cards/', { params, responseMap: 'cards', authorizationRequired: true });
    }
    bulkReadCards2(params) {
        return this.client.get('/cards/', { params, responseMap: 'cards', authorizationRequired: true });
    }
    bulkReadGeometriesOnly2(params) {
        return this.client.get('/cards/', { params, responseMap: 'cards', authorizationRequired: true });
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
    readCard2(cardId, params) {
        return this.client.get(`/cards/${cardId}`, { params, authorizationRequired: true });
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
        return this.client.getDataState('/categories/', { responseMap: 'categories', authorizationRequired: true });
    }
    bulkReadCategories2() {
        return this.client.get('/categories/', { responseMap: 'categories', authorizationRequired: true });
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
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b8dec3cf13d1897109220787f995546558de477d/cosphere_entity_service/category/serializers.py/#lines-27
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/views/donation.py/#lines-30
 */
var CheckIfCanAttemptDonationQueryEvent;
(function (CheckIfCanAttemptDonationQueryEvent) {
    CheckIfCanAttemptDonationQueryEvent["CLOSE"] = "CLOSE";
    CheckIfCanAttemptDonationQueryEvent["RECALL"] = "RECALL";
    CheckIfCanAttemptDonationQueryEvent["START"] = "START";
})(CheckIfCanAttemptDonationQueryEvent || (CheckIfCanAttemptDonationQueryEvent = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/serializers/payment.py/#lines-9
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/serializers/payment.py/#lines-9
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/views/donation.py/#lines-184
 */
var CreateDonationattemptBodyEvent;
(function (CreateDonationattemptBodyEvent) {
    CreateDonationattemptBodyEvent["CLOSE"] = "CLOSE";
    CreateDonationattemptBodyEvent["RECALL"] = "RECALL";
    CreateDonationattemptBodyEvent["START"] = "START";
})(CreateDonationattemptBodyEvent || (CreateDonationattemptBodyEvent = {}));
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/serializers/donation.py/#lines-8
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
            .post('/external/auth_tokens/authorize/', {}, { authorizationRequired: false });
        // .pipe(filter(x => !_.isEmpty(x)));
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
        return this.client.getDataState('/fragments/', { params, responseMap: 'fragments', authorizationRequired: true });
    }
    bulkReadFragments2(params) {
        return this.client.get('/fragments/', { params, responseMap: 'fragments', authorizationRequired: true });
    }
    /**
     * List Published Remote Fragments
     * -------------
     *
     * List Published Remote Fragments
     */
    bulkReadPublishedFragments(params) {
        return this.client.getDataState('/fragments/published/', { params, responseMap: 'fragments', authorizationRequired: false });
    }
    bulkReadPublishedFragments2(params) {
        return this.client.get('/fragments/published/', { params, responseMap: 'fragments', authorizationRequired: false });
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
        return this.client.getDataState('/grid/geometries/', { params, responseMap: 'geometries', authorizationRequired: true });
    }
    bulkReadGeometries2(params) {
        return this.client.get('/grid/geometries/', { params, responseMap: 'geometries', authorizationRequired: true });
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
        return this.client.getDataState('/hashtags/', { params, responseMap: 'hashtags', authorizationRequired: true });
    }
    bulkReadHashtags2(params) {
        return this.client.get('/hashtags/', { params, responseMap: 'hashtags', authorizationRequired: true });
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
        return this.client.getDataState('/hashtags/toc', { params, authorizationRequired: true });
    }
    readHashtagsToc2(params) {
        return this.client.get('/hashtags/toc', { params, authorizationRequired: true });
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
class InternalDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Clear all Entries for a given User
     * -------------
     *
     * Internal view enabling one to clean up all database entries for a specific `user_id`. It must be of the utmost importance that this endpoint would not be available on the production system.
     */
    deleteEntriesForUser(userId) {
        return this.client
            .delete(`/reset/${userId}`, { authorizationRequired: true })
            .pipe(filter(x => !isEmpty(x)));
    }
}
InternalDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
InternalDomain.ctorParameters = () => [
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/serializers/invoice.py/#lines-53
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
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b8dec3cf13d1897109220787f995546558de477d/cosphere_entity_service/grid/serializers.py/#lines-8
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
    readMediaitemByProcessId(processId) {
        return this.client.getDataState(`/mediaitems/by_process/${processId}`, { authorizationRequired: true });
    }
    readMediaitemByProcessId2(processId) {
        return this.client.get(`/mediaitems/by_process/${processId}`, { authorizationRequired: true });
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
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b023ad5da15027683028609c140260b0a1808452/cosphere_fragment_service/notification/serializers.py/#lines-46
 */
var BulkReadNotificationsResponseKind;
(function (BulkReadNotificationsResponseKind) {
    BulkReadNotificationsResponseKind["FRAGMENT_UPDATE"] = "FRAGMENT_UPDATE";
})(BulkReadNotificationsResponseKind || (BulkReadNotificationsResponseKind = {}));

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
        return this.client.getDataState('/paths/', { params, responseMap: 'paths', authorizationRequired: true });
    }
    bulkReadPaths2(params) {
        return this.client.get('/paths/', { params, responseMap: 'paths', authorizationRequired: true });
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/serializers/payment_card.py/#lines-75
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/serializers/payment_card.py/#lines-9
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/serializers/payment.py/#lines-9
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
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/views/subscription.py/#lines-28
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
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b8dec3cf13d1897109220787f995546558de477d/cosphere_entity_service/task/views.py/#lines-33
 */
var BulkReadTasksQueryQueueType;
(function (BulkReadTasksQueryQueueType) {
    BulkReadTasksQueryQueueType["DN"] = "DN";
    BulkReadTasksQueryQueueType["HP"] = "HP";
    BulkReadTasksQueryQueueType["OT"] = "OT";
    BulkReadTasksQueryQueueType["PR"] = "PR";
})(BulkReadTasksQueryQueueType || (BulkReadTasksQueryQueueType = {}));
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b8dec3cf13d1897109220787f995546558de477d/cosphere_entity_service/task/serializers.py/#lines-55
 */
var BulkReadTasksResponseQueueType;
(function (BulkReadTasksResponseQueueType) {
    BulkReadTasksResponseQueueType["DN"] = "DN";
    BulkReadTasksResponseQueueType["HP"] = "HP";
    BulkReadTasksResponseQueueType["OT"] = "OT";
    BulkReadTasksResponseQueueType["PR"] = "PR";
})(BulkReadTasksResponseQueueType || (BulkReadTasksResponseQueueType = {}));
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b8dec3cf13d1897109220787f995546558de477d/cosphere_entity_service/task/views.py/#lines-33
 */
var BulkReadTaskBinsQueryQueueType;
(function (BulkReadTaskBinsQueryQueueType) {
    BulkReadTaskBinsQueryQueueType["DN"] = "DN";
    BulkReadTaskBinsQueryQueueType["HP"] = "HP";
    BulkReadTaskBinsQueryQueueType["OT"] = "OT";
    BulkReadTaskBinsQueryQueueType["PR"] = "PR";
})(BulkReadTaskBinsQueryQueueType || (BulkReadTaskBinsQueryQueueType = {}));
/**
 * https://bitbucket.org/goodai/cosphere-entity-service/src/b8dec3cf13d1897109220787f995546558de477d/cosphere_entity_service/task/serializers.py/#lines-71
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
    readCard2(cardId, params) {
        return this.cardsDomain.readCard2(cardId, params);
    }
    bulkReadGeometriesOnly2(params) {
        return this.cardsDomain.bulkReadGeometriesOnly2(params);
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
    get internalDomain() {
        if (!this._internalDomain) {
            this._internalDomain = this.injector.get(InternalDomain);
        }
        return this._internalDomain;
    }
    deleteEntriesForUser(userId) {
        return this.internalDomain.deleteEntriesForUser(userId);
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
    readMediaitemByProcessId(processId) {
        return this.mediaitemsDomain.readMediaitemByProcessId(processId);
    }
    readMediaitemByProcessId2(processId) {
        return this.mediaitemsDomain.readMediaitemByProcessId2(processId);
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
// export function configFactory(config: Config) {
//   return new ConfigService(config);
// }
class ClientModule {
    static forRoot(config) {
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
    }
}
ClientModule.decorators = [
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

/**
 * Generated bundle index. Do not edit.
 */

export { ClientModule, ClientService, APIService, AccountSettingsDomain, AccountsDomain, BulkReadAccountsResponseAtype, ReadAccountResponseAtype, UpdateAccountResponseAtype, AttemptStatsDomain, AttemptsDomain, AuthTokensDomain, CardsDomain, CategoriesDomain, BulkReadCategoriesResponseText, ContactsDomain, DonationsDomain, CheckIfCanAttemptDonationQueryEvent, CreateAnonymousDonationResponseCurrency, CreateAnonymousDonationResponseProductType, CreateAnonymousDonationResponseStatus, CreateDonationResponseCurrency, CreateDonationResponseProductType, CreateDonationResponseStatus, CreateDonationattemptBodyEvent, CreateDonationattemptResponseEvent, ExternalAppsDomain, FocusRecordsDomain, FragmentHashtagsDomain, FragmentWordsDomain, FragmentsDomain, GeometriesDomain, HashtagsDomain, InternalDomain, InvoicesDomain, BulkReadInvoicesResponseCurrency, BulkReadInvoicesResponseProductType, LinksDomain, ReadOrCreateLinkResponseKind, MediaitemsDomain, NotificationsDomain, BulkReadNotificationsResponseKind, PathsDomain, PaymentCardsDomain, BulkReadPaymentcardsResponseCurrency, BulkReadPaymentcardsResponseProductType, BulkReadPaymentcardsResponseStatus, CreatePaymentcardResponseCurrency, CreatePaymentcardResponseProductType, CreatePaymentcardResponseStatus, PayWithDefaultPaymentCardResponseCurrency, PayWithDefaultPaymentCardResponseProductType, PayWithDefaultPaymentCardResponseStatus, PaymentsDomain, RecallDomain, SubscriptionsDomain, ChangeSubscriptionBodySubscriptionType, TasksDomain, BulkReadTasksQueryQueueType, BulkReadTasksResponseQueueType, BulkReadTaskBinsQueryQueueType, BulkReadTaskBinsResponseQueueType, WordsDomain };

//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29zcGhlcmUtY2xpZW50LmpzLm1hcCIsInNvdXJjZXMiOlsibmc6Ly9AY29zcGhlcmUvY2xpZW50L3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvYWNjb3VudF9zZXR0aW5ncy9hY2NvdW50X3NldHRpbmdzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2FjY291bnRzL2FjY291bnRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2FjY291bnRzL2FjY291bnRzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2F0dGVtcHRfc3RhdHMvYXR0ZW1wdF9zdGF0cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hdHRlbXB0cy9hdHRlbXB0cy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9hdXRoX3Rva2Vucy9hdXRoX3Rva2Vucy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9jYXJkcy9jYXJkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9jYXRlZ29yaWVzL2NhdGVnb3JpZXMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvY2F0ZWdvcmllcy9jYXRlZ29yaWVzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2NvbnRhY3RzL2NvbnRhY3RzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2RvbmF0aW9ucy9kb25hdGlvbnMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZG9uYXRpb25zL2RvbmF0aW9ucy5tb2RlbHMudHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9leHRlcm5hbF9hcHBzL2V4dGVybmFsX2FwcHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZm9jdXNfcmVjb3Jkcy9mb2N1c19yZWNvcmRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ZyYWdtZW50X2hhc2h0YWdzL2ZyYWdtZW50X2hhc2h0YWdzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ZyYWdtZW50X3dvcmRzL2ZyYWdtZW50X3dvcmRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ZyYWdtZW50cy9mcmFnbWVudHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvZ2VvbWV0cmllcy9nZW9tZXRyaWVzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2hhc2h0YWdzL2hhc2h0YWdzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ludGVybmFsL2ludGVybmFsLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ludm9pY2VzL2ludm9pY2VzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2ludm9pY2VzL2ludm9pY2VzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2xpbmtzL2xpbmtzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL2xpbmtzL2xpbmtzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL21lZGlhaXRlbXMvbWVkaWFpdGVtcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9ub3RpZmljYXRpb25zL25vdGlmaWNhdGlvbnMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvbm90aWZpY2F0aW9ucy9ub3RpZmljYXRpb25zLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3BhdGhzL3BhdGhzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3BheW1lbnRfY2FyZHMvcGF5bWVudF9jYXJkcy5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9wYXltZW50X2NhcmRzL3BheW1lbnRfY2FyZHMubW9kZWxzLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcGF5bWVudHMvcGF5bWVudHMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvcmVjYWxsL3JlY2FsbC5kb21haW4udHMiLCJuZzovL0Bjb3NwaGVyZS9jbGllbnQvZG9tYWlucy9zdWJzY3JpcHRpb25zL3N1YnNjcmlwdGlvbnMuZG9tYWluLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2RvbWFpbnMvc3Vic2NyaXB0aW9ucy9zdWJzY3JpcHRpb25zLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3Rhc2tzL3Rhc2tzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3Rhc2tzL3Rhc2tzLm1vZGVscy50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9kb21haW5zL3dvcmRzL3dvcmRzLmRvbWFpbi50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9zZXJ2aWNlcy9hcGkuc2VydmljZS50cyIsIm5nOi8vQGNvc3BoZXJlL2NsaWVudC9jbGllbnQubW9kdWxlLnRzIiwibmc6Ly9AY29zcGhlcmUvY2xpZW50L2Nvc3BoZXJlLWNsaWVudC50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBJbmplY3QgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7XG4gIEh0dHBDbGllbnQsXG4gIEh0dHBQYXJhbXMsXG4gIEh0dHBIZWFkZXJzLFxuICBIdHRwRXJyb3JSZXNwb25zZVxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBCZWhhdmlvclN1YmplY3QsIFN1YmplY3QsIE9ic2VydmFibGUsIHRocm93RXJyb3IgfSBmcm9tICdyeGpzJztcbmltcG9ydCB7IGNhdGNoRXJyb3IsIHJldHJ5LCBtYXAgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDb25maWcgfSBmcm9tICcuL2NvbmZpZy5zZXJ2aWNlJztcbmltcG9ydCB7IE9wdGlvbnMsIFN0YXRlLCBEYXRhU3RhdGUsIFJlcXVlc3RTdGF0ZSB9IGZyb20gJy4vY2xpZW50LmludGVyZmFjZSc7XG5cbkBJbmplY3RhYmxlKHtcbiAgcHJvdmlkZWRJbjogJ3Jvb3QnXG59KVxuZXhwb3J0IGNsYXNzIENsaWVudFNlcnZpY2Uge1xuICAvKipcbiAgICogU3RhdGUgZm9yIGFsbCBHRVQgcGF5bG9hZHNcbiAgICovXG4gIHN0YXRlID0gbmV3IE1hcDxzdHJpbmcsIFN0YXRlPGFueT4+KCk7XG5cbiAgcmVhZG9ubHkgYmFzZVVybDogc3RyaW5nO1xuICByZWFkb25seSBhdXRoVG9rZW46IHN0cmluZztcblxuICBwcml2YXRlIHJlYWRvbmx5IGRlZmF1bHRBdXRoVG9rZW46IHN0cmluZyA9ICdhdXRoX3Rva2VuJztcblxuICAvKipcbiAgICogQ2FjaGUgdGltZSAtIGV2ZXJ5IEdFVCByZXF1ZXN0IGlzIHRha2VuIG9ubHkgaWYgdGhlIGxhc3Qgb25lXG4gICAqIHdhcyBpbnZva2VkIG5vdCBlYXJsaWVyIHRoZW4gYGNhY2hlVGltZWAgbWlucyBhZ28uXG4gICAqIE9ubHkgc3VjY2Vzc2Z1bCByZXNwb25zZXMgYXJlIGNhY2hlZCAoMnh4KVxuICAgKi9cbiAgcHJpdmF0ZSByZWFkb25seSBjYWNoZVRpbWUgPSAxMDAwICogNjAgKiA2MDsgLy8gNjAgbWluc1xuXG4gIGNvbnN0cnVjdG9yKEBJbmplY3QoJ2NvbmZpZycpIHByaXZhdGUgY29uZmlnOiBDb25maWcsIHByaXZhdGUgaHR0cDogSHR0cENsaWVudCkge1xuICAgIHRoaXMuYmFzZVVybCA9IHRoaXMuY29uZmlnLmJhc2VVcmw7XG4gICAgdGhpcy5hdXRoVG9rZW4gPVxuICAgICAgdGhpcy5jb25maWcuYXV0aFRva2VuIHx8IHRoaXMuZGVmYXVsdEF1dGhUb2tlbjtcbiAgfVxuXG4gIGdldDxUPihlbmRwb2ludDogc3RyaW5nLCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLmdldCh1cmwsIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBwb3N0PFQ+KGVuZHBvaW50OiBzdHJpbmcsIGJvZHk6IGFueSwgb3B0aW9ucz86IE9wdGlvbnMpOiBPYnNlcnZhYmxlPFQ+IHtcbiAgICBjb25zdCB1cmwgPSB0aGlzLmdldFVybChlbmRwb2ludCk7XG4gICAgY29uc3QgaHR0cE9wdGlvbnMgPSB0aGlzLmdldEh0dHBPcHRpb25zKG9wdGlvbnMpO1xuICAgIHJldHVybiB0aGlzLmh0dHBcbiAgICAgIC5wb3N0KHVybCwgYm9keSwgaHR0cE9wdGlvbnMpXG4gICAgICAucGlwZShyZXRyeSgzKSwgY2F0Y2hFcnJvcih0aGlzLmhhbmRsZUVycm9yKSkgYXMgT2JzZXJ2YWJsZTxUPjtcbiAgfVxuXG4gIHB1dDxUPihlbmRwb2ludDogc3RyaW5nLCBib2R5OiBhbnksIG9wdGlvbnM/OiBPcHRpb25zKTogT2JzZXJ2YWJsZTxUPiB7XG4gICAgY29uc3QgdXJsID0gdGhpcy5nZXRVcmwoZW5kcG9pbnQpO1xuICAgIGNvbnN0IGh0dHBPcHRpb25zID0gdGhpcy5nZXRIdHRwT3B0aW9ucyhvcHRpb25zKTtcbiAgICByZXR1cm4gdGhpcy5odHRwXG4gICAgICAucHV0KHVybCwgYm9keSwgaHR0cE9wdGlvbnMpXG4gICAgICAucGlwZShyZXRyeSgzKSwgY2F0Y2hFcnJvcih0aGlzLmhhbmRsZUVycm9yKSkgYXMgT2JzZXJ2YWJsZTxUPjtcbiAgfVxuXG4gIGRlbGV0ZTxUPihlbmRwb2ludDogc3RyaW5nLCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLmRlbGV0ZSh1cmwsIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBnZXREYXRhU3RhdGU8VD4oZW5kcG9pbnQ6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiBEYXRhU3RhdGU8VD4ge1xuICAgIGNvbnN0IGtleSA9IG9wdGlvbnMgJiYgb3B0aW9ucy5wYXJhbXMgPyBgJHtlbmRwb2ludH1fJHtKU09OLnN0cmluZ2lmeShvcHRpb25zLnBhcmFtcyl9YCA6IGVuZHBvaW50O1xuICAgIHRoaXMuaW5pdFN0YXRlKGtleSwgb3B0aW9ucyk7XG5cbiAgICBsZXQgY2FjaGUgPSB0cnVlO1xuICAgIGxldCBwYXJhbXM6IEh0dHBQYXJhbXMgfCB7IFtwYXJhbTogc3RyaW5nXTogc3RyaW5nIHwgc3RyaW5nW10gfTtcblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAnY2FjaGUnKSkge1xuICAgICAgY2FjaGUgPSBvcHRpb25zLmNhY2hlO1xuICAgIH1cblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAncGFyYW1zJykpIHtcbiAgICAgIHBhcmFtcyA9IG9wdGlvbnMucGFyYW1zO1xuICAgIH1cblxuICAgIC8vIEdldCB0aGUgZW5kcG9pbnQgc3RhdGVcbiAgICBjb25zdCBzdGF0ZSA9IHRoaXMuc3RhdGUuZ2V0KGtleSk7XG5cbiAgICAvLyBEbyBub3QgYWxsb3cgaW52b2tlIHRoZSBzYW1lIEdFVCByZXF1ZXN0IHdoaWxlIG9uZSBpcyBwZW5kaW5nXG4gICAgaWYgKHN0YXRlLnJlcXVlc3RTdGF0ZS5wZW5kaW5nIC8qJiYgIV8uaXNFbXB0eShwYXJhbXMpKi8pIHtcbiAgICAgIHJldHVybiBzdGF0ZS5kYXRhU3RhdGU7XG4gICAgfVxuXG4gICAgY29uc3QgY3VycmVudFRpbWUgPSArbmV3IERhdGUoKTtcbiAgICBpZiAoXG4gICAgICBjdXJyZW50VGltZSAtIHN0YXRlLnJlcXVlc3RTdGF0ZS5jYWNoZWRBdCA+IHRoaXMuY2FjaGVUaW1lIHx8XG4gICAgICAvLyAhXy5pc0VtcHR5KHBhcmFtcykgfHxcbiAgICAgICFjYWNoZVxuICAgICkge1xuICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLnBlbmRpbmcgPSB0cnVlO1xuICAgICAgdGhpcy5nZXQoZW5kcG9pbnQsIG9wdGlvbnMpXG4gICAgICAgIC5waXBlKFxuICAgICAgICAgIG1hcChkYXRhID0+IChvcHRpb25zLnJlc3BvbnNlTWFwID8gZGF0YVtvcHRpb25zLnJlc3BvbnNlTWFwXSA6IGRhdGEpKVxuICAgICAgICApXG4gICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgZGF0YSA9PiB7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuZGF0YSQubmV4dChkYXRhKTtcbiAgICAgICAgICAgIHN0YXRlLmRhdGFTdGF0ZS5pc0RhdGEkLm5leHQoIV8uaXNFbXB0eShkYXRhKSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUubG9hZGluZyQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyA9IGZhbHNlO1xuICAgICAgICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLmNhY2hlZEF0ID0gY3VycmVudFRpbWU7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmlzRGF0YSQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuZGF0YSQuZXJyb3IobnVsbCk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUubG9hZGluZyQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyA9IGZhbHNlO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc3RhdGUuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQoZmFsc2UpO1xuICAgIH1cblxuICAgIHJldHVybiBzdGF0ZS5kYXRhU3RhdGU7XG4gIH1cblxuICBwcml2YXRlIGluaXRTdGF0ZShrZXk6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMuc3RhdGUuaGFzKGtleSkpIHtcbiAgICAgIHRoaXMuc3RhdGUuc2V0KGtleSwge1xuICAgICAgICBkYXRhU3RhdGU6IHtcbiAgICAgICAgICBsb2FkaW5nJDogbmV3IEJlaGF2aW9yU3ViamVjdCh0cnVlKSxcbiAgICAgICAgICBpc0RhdGEkOiBuZXcgQmVoYXZpb3JTdWJqZWN0KGZhbHNlKSxcbiAgICAgICAgICBkYXRhJDogbmV3IEJlaGF2aW9yU3ViamVjdChudWxsKVxuICAgICAgICB9LFxuICAgICAgICByZXF1ZXN0U3RhdGU6IHtcbiAgICAgICAgICBjYWNoZWRBdDogMCxcbiAgICAgICAgICBwZW5kaW5nOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5zdGF0ZS5nZXQoa2V5KS5kYXRhU3RhdGUubG9hZGluZyQubmV4dCh0cnVlKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGdldEh0dHBPcHRpb25zKFxuICAgIG9wdGlvbnM/OiBPcHRpb25zXG4gICk6IHtcbiAgICBwYXJhbXM/OiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgaGVhZGVycz86IEh0dHBIZWFkZXJzIHwgeyBbaGVhZGVyOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgIHJlcG9ydFByb2dyZXNzPzogYm9vbGVhbjtcbiAgfSB7XG4gICAgY29uc3QgYXV0aG9yaXphdGlvblJlcXVpcmVkID0gXy5oYXMob3B0aW9ucywgJ2F1dGhvcml6YXRpb25SZXF1aXJlZCcpXG4gICAgICA/IG9wdGlvbnMuYXV0aG9yaXphdGlvblJlcXVpcmVkXG4gICAgICA6IHRydWU7XG4gICAgY29uc3QgZXRhZyA9IChvcHRpb25zICYmIG9wdGlvbnMuZXRhZykgfHwgdW5kZWZpbmVkO1xuXG4gICAgbGV0IGh0dHBPcHRpb25zOiB7XG4gICAgICBwYXJhbXM/OiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgICBoZWFkZXJzPzogSHR0cEhlYWRlcnMgfCB7IFtoZWFkZXI6IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgICByZXBvcnRQcm9ncmVzcz86IGJvb2xlYW47XG4gICAgfSA9IHtcbiAgICAgIGhlYWRlcnM6IHRoaXMuZ2V0SGVhZGVycyhhdXRob3JpemF0aW9uUmVxdWlyZWQsIGV0YWcpXG4gICAgfTtcblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAnaGVhZGVycycpKSB7XG4gICAgICAvLyB0c2xpbnQ6ZGlzYWJsZVxuICAgICAgZm9yIChsZXQga2V5IGluIG9wdGlvbnMuaGVhZGVycykge1xuICAgICAgICBodHRwT3B0aW9ucy5oZWFkZXJzW2tleV0gPSAoPGFueT5vcHRpb25zKS5oZWFkZXJzW2tleV07XG4gICAgICB9XG4gICAgICAvLyB0c2xpbnQ6ZW5hYmxlXG4gICAgfVxuXG4gICAgaWYgKF8uaGFzKG9wdGlvbnMsICdwYXJhbXMnKSkge1xuICAgICAgaHR0cE9wdGlvbnMucGFyYW1zID0gb3B0aW9ucy5wYXJhbXM7XG4gICAgfVxuXG4gICAgaWYgKF8uaGFzKG9wdGlvbnMsICdyZXBvcnRQcm9ncmVzcycpKSB7XG4gICAgICBodHRwT3B0aW9ucy5yZXBvcnRQcm9ncmVzcyA9IG9wdGlvbnMucmVwb3J0UHJvZ3Jlc3M7XG4gICAgfVxuXG4gICAgcmV0dXJuIGh0dHBPcHRpb25zO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRIZWFkZXJzKFxuICAgIGF1dGhvcml6YXRpb25SZXF1aXJlZDogYm9vbGVhbixcbiAgICBldGFnPzogc3RyaW5nXG4gICk6IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH0ge1xuICAgIGxldCBoZWFkZXJzID0ge1xuICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJ1xuICAgIH07XG5cbiAgICBpZiAoYXV0aG9yaXphdGlvblJlcXVpcmVkKSB7XG4gICAgICBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSBgQmVhcmVyICR7dGhpcy5nZXRUb2tlbigpfWA7XG4gICAgfVxuXG4gICAgaWYgKGV0YWcpIHtcbiAgICAgIGhlYWRlcnNbJ0VUYWcnXSA9IGV0YWc7XG4gICAgfVxuXG4gICAgcmV0dXJuIGhlYWRlcnM7XG4gIH1cblxuICBwcml2YXRlIGdldFVybChlbmRwb2ludDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5iYXNlVXJsfSR7ZW5kcG9pbnR9YDtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0VG9rZW4oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0odGhpcy5hdXRoVG9rZW4pO1xuICB9XG5cbiAgcHJpdmF0ZSBoYW5kbGVFcnJvcihlcnJvcjogSHR0cEVycm9yUmVzcG9uc2UpIHtcbiAgICBpZiAoZXJyb3IuZXJyb3IgaW5zdGFuY2VvZiBFcnJvckV2ZW50KSB7XG4gICAgICAvLyBBIGNsaWVudC1zaWRlIG9yIG5ldHdvcmsgZXJyb3Igb2NjdXJyZWQuIEhhbmRsZSBpdCBhY2NvcmRpbmdseS5cbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0FuIGVycm9yIG9jY3VycmVkOicsIGVycm9yLmVycm9yLm1lc3NhZ2UpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBUaGUgYmFja2VuZCByZXR1cm5lZCBhbiB1bnN1Y2Nlc3NmdWwgcmVzcG9uc2UgY29kZS5cbiAgICAgIC8vIFRoZSByZXNwb25zZSBib2R5IG1heSBjb250YWluIGNsdWVzIGFzIHRvIHdoYXQgd2VudCB3cm9uZyxcbiAgICAgIGNvbnNvbGUuZXJyb3IoXG4gICAgICAgIGBCYWNrZW5kIHJldHVybmVkIGNvZGUgJHtlcnJvci5zdGF0dXN9LCBgICsgYGJvZHkgd2FzOiAke2Vycm9yLmVycm9yfWBcbiAgICAgICk7XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGFuIG9ic2VydmFibGUgd2l0aCBhIHVzZXItZmFjaW5nIGVycm9yIG1lc3NhZ2VcbiAgICByZXR1cm4gdGhyb3dFcnJvcignU29tZXRoaW5nIGJhZCBoYXBwZW5lZDsgcGxlYXNlIHRyeSBhZ2FpbiBsYXRlci4nKTtcbiAgfVxufVxuIiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBY2NvdW50IFNldHRpbmdzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2FjY291bnRfc2V0dGluZ3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEFjY291bnRTZXR0aW5nc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEFjY291bnQgU2V0dGluZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEFjY291bnRzZXR0aW5nKCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkQWNjb3VudHNldHRpbmdSZXNwb25zZT4oJy9hY2NvdW50L3NldHRpbmdzLycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEFjY291bnRzZXR0aW5nMigpOiBPYnNlcnZhYmxlPFguUmVhZEFjY291bnRzZXR0aW5nUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPignL2FjY291bnQvc2V0dGluZ3MvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIEFjY291bnQgU2V0dGluZ3NcbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQWNjb3VudHNldHRpbmcoYm9keTogWC5VcGRhdGVBY2NvdW50c2V0dGluZ0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQWNjb3VudHNldHRpbmdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPignL2FjY291bnQvc2V0dGluZ3MvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEFjY291bnRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2FjY291bnRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBY2NvdW50c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBY3RpdmF0ZSBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQWN0aXZhdGUgQWNjb3VudCBieSBkZWNvZGluZyB0aGUgYGNvZGVgIHdoaWNoIGNvbnRhaW5zIHRoZSBjb25maXJtYXRpb24gb2ZmIHRoZSBpbnRlbnQgYW5kIHdhcyBzaWduZWQgYnkgdGhlIHVzZXIgaXRzZWxmLlxuICAgICAqL1xuICAgIHB1YmxpYyBhY3RpdmF0ZUFjY291bnQoYm9keTogWC5BY3RpdmF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkFjdGl2YXRlQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5BY3RpdmF0ZUFjY291bnRSZXNwb25zZT4oJy9hdXRoL2FjdGl2YXRlLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBNZW50b3JzJyBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlIG9uZSB0byBSZWFkIGFsbCBhdmFpbGFibGUgTWVudG9yIGFjY291bnRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQWNjb3VudHMocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9hdXRoL2FjY291bnRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEFjY291bnRzMihwYXJhbXM6IFguQnVsa1JlYWRBY2NvdW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9hdXRoL2FjY291bnRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ2hhbmdlIFBhc3N3b3JkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY2hhbmdlIG9uZSdzIHBhc3N3b3JkIGZvciBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIGNoYW5nZVBhc3N3b3JkKGJvZHk6IFguQ2hhbmdlUGFzc3dvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNoYW5nZVBhc3N3b3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNoYW5nZVBhc3N3b3JkUmVzcG9uc2U+KCcvYXV0aC9jaGFuZ2VfcGFzc3dvcmQvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgQWNjb3VudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZXMgVXNlciBhbmQgQWNjb3VudCBpZiBwcm92aWRlZCBkYXRhIGFyZSB2YWxpZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQWNjb3VudChib2R5OiBYLkNyZWF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlQWNjb3VudFJlc3BvbnNlPignL2F1dGgvYWNjb3VudHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBNeSBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBteSBBY2NvdW50IGRhdGEuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRBY2NvdW50KCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY2NvdW50cy9tZS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRBY2NvdW50MigpOiBPYnNlcnZhYmxlPFguUmVhZEFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEFjY291bnRSZXNwb25zZT4oJy9hdXRoL2FjY291bnRzL21lLycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlc2V0IFBhc3N3b3JkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gcmVzZXQgaGVyIHBhc3N3b3JkIGluIGNhc2UgdGhlIG9sZCBvbmUgY2Fubm90IGJlIHJlY2FsbGVkLlxuICAgICAqL1xuICAgIHB1YmxpYyByZXNldFBhc3N3b3JkKGJvZHk6IFguUmVzZXRQYXNzd29yZEJvZHkpOiBPYnNlcnZhYmxlPFguUmVzZXRQYXNzd29yZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5SZXNldFBhc3N3b3JkUmVzcG9uc2U+KCcvYXV0aC9yZXNldF9wYXNzd29yZC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTZW5kIEFjY291bnQgQWN0aXZhdGlvbiBFbWFpbFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFNlbmQgYW4gRW1haWwgY29udGFpbmluZyB0aGUgY29uZmlybWF0aW9uIGxpbmsgd2hpY2ggd2hlbiBjbGlja2VkIGtpY2tzIG9mIHRoZSBBY2NvdW50IEFjdGl2YXRpb24uIEV2ZW4gdGhvdWdoIHRoZSBhY3RpdmF0aW9uIGVtYWlsIGlzIHNlbmQgYXV0b21hdGljYWxseSBkdXJpbmcgdGhlIFNpZ24gVXAgcGhhc2Ugb25lIHNob3VsZCBoYXZlIGEgd2F5IHRvIHNlbmQgaXQgYWdhaW4gaW4gY2FzZSBpdCB3YXMgbm90IGRlbGl2ZXJlZC5cbiAgICAgKi9cbiAgICBwdWJsaWMgc2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWwoYm9keTogWC5TZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguU2VuZEFjY291bnRBY3RpdmF0aW9uRW1haWxSZXNwb25zZT4oJy9hdXRoL3NlbmRfYWN0aXZhdGlvbl9lbWFpbC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTZW5kIFJlc2V0IFBhc3N3b3JkIEVtYWlsXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2VuZCBhbiBFbWFpbCBjb250YWluaW5nIHRoZSBjb25maXJtYXRpb24gbGluayB3aGljaCB3aGVuIGNsaWNrZWQga2lja3Mgb2YgdGhlIHJlYWwgUmVzZXQgUGFzc3dvcmQgb3BlcmF0aW9uLlxuICAgICAqL1xuICAgIHB1YmxpYyBzZW5kUmVzZXRQYXNzd29yZEVtYWlsKGJvZHk6IFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbEJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZFJlc2V0UGFzc3dvcmRFbWFpbFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5TZW5kUmVzZXRQYXNzd29yZEVtYWlsUmVzcG9uc2U+KCcvYXV0aC9zZW5kX3Jlc2V0X3Bhc3N3b3JkX2VtYWlsLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBNeSBBY2NvdW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIG15IEFjY291bnQgZGF0YS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlQWNjb3VudChib2R5OiBYLlVwZGF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVBY2NvdW50UmVzcG9uc2U+KCcvYXV0aC9hY2NvdW50cy9tZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQWNjb3VudHMgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9hY3RpdmF0ZV9hY2NvdW50LnB5LyNsaW5lcy05MVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQWN0aXZhdGVBY2NvdW50Qm9keSB7XG4gICAgY29kZTogc3RyaW5nO1xuICAgIGVtYWlsOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEFjdGl2YXRlQWNjb3VudFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvYWNjb3VudC5weS8jbGluZXMtMTc4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEFjY291bnRzUXVlcnkge1xuICAgIHVzZXJfaWRzOiBudW1iZXJbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC9zZXJpYWxpemVycy5weS8jbGluZXMtMjNcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZEFjY291bnRzUmVzcG9uc2VBdHlwZSB7XG4gICAgQURNSU4gPSAnQURNSU4nLFxuICAgIEZSRUUgPSAnRlJFRScsXG4gICAgTEVBUk5FUiA9ICdMRUFSTkVSJyxcbiAgICBNRU5UT1IgPSAnTUVOVE9SJyxcbiAgICBQQVJUTkVSID0gJ1BBUlRORVInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eSB7XG4gICAgYXR5cGU/OiBCdWxrUmVhZEFjY291bnRzUmVzcG9uc2VBdHlwZTtcbiAgICBhdmF0YXJfdXJpPzogc3RyaW5nO1xuICAgIHNob3dfaW5fcmFua2luZz86IGJvb2xlYW47XG4gICAgdXNlcl9pZD86IGFueTtcbiAgICB1c2VybmFtZT86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZEFjY291bnRzUmVzcG9uc2Uge1xuICAgIGRhdGE6IEJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2NoYW5nZV9wYXNzd29yZC5weS8jbGluZXMtMjRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENoYW5nZVBhc3N3b3JkQm9keSB7XG4gICAgcGFzc3dvcmQ6IHN0cmluZztcbiAgICBwYXNzd29yZF9hZ2Fpbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDaGFuZ2VQYXNzd29yZFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvYWNjb3VudC5weS8jbGluZXMtMTE0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVBY2NvdW50Qm9keSB7XG4gICAgZW1haWw6IHN0cmluZztcbiAgICBwYXNzd29yZDogc3RyaW5nO1xuICAgIHBhc3N3b3JkX2FnYWluOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZUFjY291bnRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy04XG4gKi9cblxuZXhwb3J0IGVudW0gUmVhZEFjY291bnRSZXNwb25zZUF0eXBlIHtcbiAgICBBRE1JTiA9ICdBRE1JTicsXG4gICAgRlJFRSA9ICdGUkVFJyxcbiAgICBMRUFSTkVSID0gJ0xFQVJORVInLFxuICAgIE1FTlRPUiA9ICdNRU5UT1InLFxuICAgIFBBUlRORVIgPSAnUEFSVE5FUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVhZEFjY291bnRSZXNwb25zZSB7XG4gICAgYXR5cGU/OiBSZWFkQWNjb3VudFJlc3BvbnNlQXR5cGU7XG4gICAgYXZhdGFyX3VyaT86IHN0cmluZztcbiAgICBzaG93X2luX3Jhbmtpbmc/OiBib29sZWFuO1xuICAgIHVzZXJfaWQ/OiBhbnk7XG4gICAgdXNlcm5hbWU/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL2FjY291bnQvdmlld3MvcmVzZXRfcGFzc3dvcmQucHkvI2xpbmVzLTk0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBSZXNldFBhc3N3b3JkQm9keSB7XG4gICAgY29kZTogc3RyaW5nO1xuICAgIGVtYWlsOiBzdHJpbmc7XG4gICAgcGFzc3dvcmQ6IHN0cmluZztcbiAgICBwYXNzd29yZF9hZ2Fpbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0zMFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVzZXRQYXNzd29yZFJlc3BvbnNlIHtcbiAgICB0b2tlbjogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9hY2NvdW50L3ZpZXdzL2FjdGl2YXRlX2FjY291bnQucHkvI2xpbmVzLTQ2XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBTZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbEJvZHkge1xuICAgIGVtYWlsOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvLnZlbnYvc3JjL2xpbHkvbGlseS9iYXNlL3NlcmlhbGl6ZXJzLnB5LyNsaW5lcy0xNThcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9yZXNldF9wYXNzd29yZC5weS8jbGluZXMtMzFcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFNlbmRSZXNldFBhc3N3b3JkRW1haWxCb2R5IHtcbiAgICBlbWFpbDogc3RyaW5nO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBTZW5kUmVzZXRQYXNzd29yZEVtYWlsUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC92aWV3cy9hY2NvdW50LnB5LyNsaW5lcy01OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgVXBkYXRlQWNjb3VudEJvZHkge1xuICAgIGF2YXRhcl91cmk/OiBzdHJpbmc7XG4gICAgc2hvd19pbl9yYW5raW5nPzogYm9vbGVhbjtcbiAgICB1c2VybmFtZT86IHN0cmluZztcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvYWNjb3VudC9zZXJpYWxpemVycy5weS8jbGluZXMtOFxuICovXG5cbmV4cG9ydCBlbnVtIFVwZGF0ZUFjY291bnRSZXNwb25zZUF0eXBlIHtcbiAgICBBRE1JTiA9ICdBRE1JTicsXG4gICAgRlJFRSA9ICdGUkVFJyxcbiAgICBMRUFSTkVSID0gJ0xFQVJORVInLFxuICAgIE1FTlRPUiA9ICdNRU5UT1InLFxuICAgIFBBUlRORVIgPSAnUEFSVE5FUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgVXBkYXRlQWNjb3VudFJlc3BvbnNlIHtcbiAgICBhdHlwZT86IFVwZGF0ZUFjY291bnRSZXNwb25zZUF0eXBlO1xuICAgIGF2YXRhcl91cmk/OiBzdHJpbmc7XG4gICAgc2hvd19pbl9yYW5raW5nPzogYm9vbGVhbjtcbiAgICB1c2VyX2lkPzogYW55O1xuICAgIHVzZXJuYW1lPzogc3RyaW5nO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQXR0ZW1wdCBTdGF0cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hdHRlbXB0X3N0YXRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBdHRlbXB0U3RhdHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBBdHRlbXB0IFN0YXRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBBdHRlbXB0IFN0YXRzIGJ5IGZpbHRlcmluZyBleGlzdGluZyBvbmVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEF0dGVtcHRzdGF0cyhwYXJhbXM6IFguQnVsa1JlYWRBdHRlbXB0c3RhdHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRfc3RhdHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkQXR0ZW1wdHN0YXRzMihwYXJhbXM6IFguQnVsa1JlYWRBdHRlbXB0c3RhdHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPignL3JlY2FsbC9hdHRlbXB0X3N0YXRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEF0dGVtcHQgU3RhdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZSBBdHRlbXB0IFN0YXQgd2hpY2ggc3RvcmVzIGluZm9ybWF0aW9uIGFib3V0IGJhc2lzIHN0YXRpc3RpY3Mgb2YgYSBwYXJ0aWN1bGFyIHJlY2FsbCBhdHRlbXB0LlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVBdHRlbXB0c3RhdChib2R5OiBYLkNyZWF0ZUF0dGVtcHRzdGF0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0c3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVBdHRlbXB0c3RhdFJlc3BvbnNlPignL3JlY2FsbC9hdHRlbXB0X3N0YXRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEV4dGVybmFsIEF0dGVtcHQgU3RhdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZSBFeHRlcm5hbCBBdHRlbXB0IFN0YXQgbWVhbmluZyBvbmUgd2hpY2ggd2FzIHJlbmRlcmVkIGVsc2V3aGVyZSBpbiBhbnkgb2YgdGhlIG11bHRpcGxlIENvU3BoZXJlIGFwcHMuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXQoYm9keTogWC5DcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUV4dGVybmFsQXR0ZW1wdFN0YXRSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdF9zdGF0cy9leHRlcm5hbC8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQXR0ZW1wdHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vYXR0ZW1wdHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF0dGVtcHRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgQXR0ZW1wdHMgQnkgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgQXR0ZW1wdHMgZm9yIGEgc3BlY2lmaWMgQ2FyZCBnaXZlbiBieSBpdHMgSWQuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+KGAvcmVjYWxsL2F0dGVtcHRzL2J5X2NhcmQvJHtjYXJkSWR9YCwgeyByZXNwb25zZU1hcDogJ2F0dGVtcHRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHMyKGNhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPihgL3JlY2FsbC9hdHRlbXB0cy9ieV9jYXJkLyR7Y2FyZElkfWAsIHsgcmVzcG9uc2VNYXA6ICdhdHRlbXB0cycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgQXR0ZW1wdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENyZWF0ZSBBdHRlbXB0IHdoaWNoIGlzIGEgcmVmbGVjdGlvbiBvZiBzb21lb25lJ3Mga25vd2xlZGdlIHJlZ2FyZGluZyBhIGdpdmVuIENhcmQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUF0dGVtcHQoYm9keTogWC5DcmVhdGVBdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUF0dGVtcHRSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgQXR0ZW1wdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSBleGlzdGluZyBBdHRlbXB0IHdpdGggbmV3IGNlbGxzIGFuZCAvIG9yIHN0eWxlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVBdHRlbXB0KGF0dGVtcHRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVBdHRlbXB0UmVzcG9uc2U+KGAvcmVjYWxsL2F0dGVtcHRzLyR7YXR0ZW1wdElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBdXRoIFRva2VucyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hdXRoX3Rva2Vucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQXV0aFRva2Vuc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBdXRob3JpemUgYSBnaXZlbiB0b2tlblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENhbiBiZSBjYWxsZWQgYnkgdGhlIEFQSSBHYXRld2F5IGluIG9yZGVyIHRvIGF1dGhvcml6ZSBldmVyeSByZXF1ZXN0IHVzaW5nIHByb3ZpZGVkIHRva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBhdXRob3JpemVBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLkF1dGhvcml6ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5BdXRob3JpemVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2F1dGhvcml6ZS8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2lnbiBJblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFZhbGlkYXRlcyBkYXRhIHByb3ZpZGVkIG9uIHRoZSBpbnB1dCBhbmQgaWYgc3VjY2Vzc2Z1bCByZXR1cm5zIGF1dGggdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEZhY2Vib29rIEF1dGggVG9rZW5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvZmFjZWJvb2svJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1vYmlsZSBGYWNlYm9vayBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2ZhY2Vib29rL21vYmlsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgR29vZ2xlIEF1dGggVG9rZW5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2dvb2dsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgTW9iaWxlIEdvb2dsZSBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlR29vZ2xlQmFzZWRNb2JpbGVBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9nb29nbGUvbW9iaWxlLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZnJlc2ggSldUIHRva2VuXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2hvdWxkIGJlIHVzZWQgd2hlbmV2ZXIgdG9rZW4gaXMgY2xvc2UgdG8gZXhwaXJ5IG9yIGlmIG9uZSBpcyByZXF1ZXN0ZWQgdG8gcmVmcmVzaCB0aGUgdG9rZW4gYmVjYXVzZSBmb3IgZXhhbXBsZSBhY2NvdW50IHR5cGUgd2FzIGNoYW5nZWQgYW5kIG5ldyB0b2tlbiBzaG91bGQgYmUgcmVxdWVzdGVkIHRvIHJlZmxlY3QgdGhhdCBjaGFuZ2UuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIENhcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2NhcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDYXJkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbW92ZSBsaXN0IG9mIENhcmRzIHNwZWNpZmllZCBieSB0aGVpciBpZHMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtEZWxldGVDYXJkcyhwYXJhbXM6IFguQnVsa0RlbGV0ZUNhcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+KCcvY2FyZHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBNdWx0aXBsZSBDYXJkc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3Qgc3Vic2V0IG9mIENhcmRzIGRlcGVuZGluZyBvbiB2YXJpb3VzIGZpbHRlcmluZyBmbGFncy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRDYXJkcyhwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPignL2NhcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2NhcmRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRDYXJkczIocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+KCcvY2FyZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnY2FyZHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEdlb21ldHJpZXNPbmx5MihwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXJkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdjYXJkcycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGluZyBhIHNpbmdsZSBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY3JlYXRlIGEgc2luZ2xlIENhcmQgaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUNhcmQoYm9keTogWC5DcmVhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUNhcmRSZXNwb25zZT4oJy9jYXJkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgQ2FyZCBieSBJZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgQ2FyZCBieSBgaWRgLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkQ2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+KGAvY2FyZHMvJHtjYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkQ2FyZDIoY2FyZElkOiBhbnksIHBhcmFtcz86IGFueSk6IE9ic2VydmFibGU8WC5SZWFkQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkQ2FyZFJlc3BvbnNlPihgL2NhcmRzLyR7Y2FyZElkfWAsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRpbmcgYSBzaW5nbGUgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGNyZWF0ZSBhIHNpbmdsZSBDYXJkIGluc3RhbmNlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVDYXJkKGNhcmRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVDYXJkUmVzcG9uc2U+KGAvY2FyZHMvJHtjYXJkSWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIENhdGVnb3JpZXMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vY2F0ZWdvcmllcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ2F0ZWdvcmllc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IENhdGVnb3JpZXNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IENhdGVnb3JpZXMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkQ2F0ZWdvcmllcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdPignL2NhdGVnb3JpZXMvJywgeyByZXNwb25zZU1hcDogJ2NhdGVnb3JpZXMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZENhdGVnb3JpZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdPignL2NhdGVnb3JpZXMvJywgeyByZXNwb25zZU1hcDogJ2NhdGVnb3JpZXMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBDYXRlZ29yaWVzIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvYjhkZWMzY2YxM2QxODk3MTA5MjIwNzg3Zjk5NTU0NjU1OGRlNDc3ZC9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS9jYXRlZ29yeS9zZXJpYWxpemVycy5weS8jbGluZXMtMjdcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZVRleHQge1xuICAgIEZPUkdPVFRFTiA9ICdGT1JHT1RURU4nLFxuICAgIEhPVCA9ICdIT1QnLFxuICAgIE5PVF9SRUNBTExFRCA9ICdOT1RfUkVDQUxMRUQnLFxuICAgIFBST0JMRU1BVElDID0gJ1BST0JMRU1BVElDJyxcbiAgICBSRUNFTlRMWV9BRERFRCA9ICdSRUNFTlRMWV9BRERFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VFbnRpdHkge1xuICAgIGNvdW50OiBudW1iZXI7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgdGV4dDogQnVsa1JlYWRDYXRlZ29yaWVzUmVzcG9uc2VUZXh0O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlIHtcbiAgICBkYXRhOiBCdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogQ29udGFjdCBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9jb250YWN0cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ29udGFjdHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEFub255bW91cyBDb250YWN0IEF0dGVtcHRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBzZW5kIG1lc3NhZ2VzIHRvIENvU3BoZXJlJ3Mgc3VwcG9ydCBldmVuIGlmIHRoZSBzZW5kZXIgaXMgbm90IGF1dGhlbnRpY2F0ZWQuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHk6IFguQ3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0UmVzcG9uc2U+KCcvY29udGFjdHMvYW5vbnltb3VzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFNlbmQgQXV0aGVudGljYXRlZCBDb250YWN0IE1lc3NhZ2VcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBTZW5kIHRoZSBDb250YWN0IE1lc3NhZ2UgaW1tZWRpYXRlbHkgc2luY2UgaXQncyBhbHJlYWR5IGZvciBhbiBleGlzdGluZyBhbmQgYXV0aGVudGljYXRlZCB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyBzZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlKGJvZHk6IFguU2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZUJvZHkpOiBPYnNlcnZhYmxlPFguU2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5TZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlUmVzcG9uc2U+KCcvY29udGFjdHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBWZXJpZnkgdGhlIGNvbnRhY3QgYXR0ZW1wdFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFZlcmlmeSB0aGUgY29ycmVjdG5lc3Mgb2YgcHJvdmlkZWQgdmVyaWZpY2F0aW9uIGNvZGUgYW5kIHNlbmQgdGhlIG1lc3NhZ2UgdG8gdGhlIENvU3BoZXJlJ3Mgc3VwcG9ydC4gVGhpcyBtZWNoYW5pc20gaXMgdXNlZCBmb3IgYW5vbnltb3VzIHVzZXJzIG9ubHkuXG4gICAgICovXG4gICAgcHVibGljIHZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHk6IFguVmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLlZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0UmVzcG9uc2U+KCcvY29udGFjdHMvYW5vbnltb3VzL3ZlcmlmeS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIERvbmF0aW9ucyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9kb25hdGlvbnMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIERvbmF0aW9uc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDaGVjayBpZiBvbmUgY2FuIGF0dGVtcHQgYSByZXF1ZXN0IGRpc3BsYXlpbmcgZG9uYXRpb25cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBTaW5jZSB3ZSBkb24ndCB3YW50IHRvIG92ZXJmbG93IHVzZXIgd2l0aCB1bm5lY2Vzc2FyeSByZXF1ZXN0cyBmb3IgaGltIGRvbmF0aW5nIHdlIGRvIGl0IGluIGEgc21hcnRlciB3YXkgdXNpbmcgc2V0IG9mIGhldXJpc3RpY3MgdGhhdCB0b2dldGhlciBoZWxwIHVzIHRvIGFuc3dlciB0aGUgZm9sbG93aW5nIHF1ZXN0aW9uOiBcIklzIGl0IHRoZSBiZXN0IG1vbWVudCB0byBhc2sgZm9yIHRoZSBkb25hdGlvbj9cIi4gQ3VycmVudGx5IHdlIHVzZSB0aGUgZm9sbG93aW5nIGhldXJpc3RpY3M6IC0gaXMgYWNjb3VudCBvbGQgZW5vdWdoPyAtIHdoZXRoZXIgdXNlciByZWNlbnRseSBkb25hdGVkIC0gd2hldGhlciB3ZSBhdHRlbXB0ZWQgcmVjZW50bHkgdG8gcmVxdWVzdCBkb25hdGlvbiBmcm9tIHRoZSB1c2VyIC0gaWYgdGhlIHVzZXIgaW4gYSBnb29kIG1vb2QgKGFmdGVyIGRvaW5nIHNvbWUgc3VjY2Vzc2Z1bCByZWNhbGxzKVxuICAgICAqL1xuICAgIHB1YmxpYyBjaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uKHBhcmFtczogWC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnkpOiBEYXRhU3RhdGU8WC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25SZXNwb25zZT4oJy9wYXltZW50cy9kb25hdGlvbnMvY2FuX2F0dGVtcHQvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb24yKHBhcmFtczogWC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnkpOiBPYnNlcnZhYmxlPFguQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvZG9uYXRpb25zL2Nhbl9hdHRlbXB0LycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVnaXN0ZXIgYW5vbnltb3VzIGRvbmF0aW9uXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogT25lIGNhbiBwZXJmb3JtIGEgZG9uYXRpb24gcGF5bWVudCBldmVuIGlmIG5vdCBiZWluZyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuIEV2ZW4gaW4gdGhhdCBjYXNlIHdlIGNhbm5vdCBhbGxvdyBmdWxsIGFub255bWl0eSBhbmQgd2UgbXVzdCByZXF1aXJlIGF0IGxlYXN0IGVtYWlsIGFkZHJlc3MgdG8gc2VuZCBpbmZvcm1hdGlvbiByZWdhcmRpbmcgdGhlIHN0YXR1cyBvZiB0aGUgcGF5bWVudC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQW5vbnltb3VzRG9uYXRpb24oYm9keTogWC5DcmVhdGVBbm9ueW1vdXNEb25hdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZT4oJy9wYXltZW50cy9kb25hdGlvbnMvcmVnaXN0ZXJfYW5vbnltb3VzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZ2lzdGVyIGRvbmF0aW9uIGZyb20gYXV0aGVudGljYXRlZCB1c2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogT25lIGNhbiBwZXJmb3JtIGEgZG9uYXRpb24gcGF5bWVudCBldmVuIGFzIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRG9uYXRpb24oYm9keTogWC5DcmVhdGVEb25hdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRG9uYXRpb25SZXNwb25zZT4oJy9wYXltZW50cy9kb25hdGlvbnMvcmVnaXN0ZXIvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgZG9uYXRpb24gYXR0ZW1wdCBmb3IgYXV0aGVudGljYXRlZCB1c2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRWFjaCBEb25hdGlvbiBBdHRlbXB0IHNob3VsZCBiZSBmb2xsb3dlZCBieSBjcmVhdGlvbiBvZiBEb25hdGlvbiBBdHRlbXB0IG1vZGVsIGluc3RhbmNlIHRvIHJlZmxlY3QgdGhhdCBmYWN0LiBJdCBhbGxvd3Mgb25lIHRvIHRyYWNrIGhvdyBtYW55IHRpbWVzIHdlIGFza2VkIGEgY2VydGFpbiB1c2VyIGFib3V0IHRoZSBkb25hdGlvbiBpbiBvcmRlciBub3QgdG8gb3ZlcmZsb3cgdGhhdCB1c2VyIHdpdGggdGhlbSBhbmQgbm90IHRvIGJlIHRvbyBhZ2dyZXNzaXZlLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVEb25hdGlvbmF0dGVtcHQoYm9keTogWC5DcmVhdGVEb25hdGlvbmF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZT4oJy9wYXltZW50cy9kb25hdGlvbnMvYXR0ZW1wdHMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIERvbmF0aW9ucyBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL2RvbmF0aW9uLnB5LyNsaW5lcy0zMFxuICovXG5cbmV4cG9ydCBlbnVtIENoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25RdWVyeUV2ZW50IHtcbiAgICBDTE9TRSA9ICdDTE9TRScsXG4gICAgUkVDQUxMID0gJ1JFQ0FMTCcsXG4gICAgU1RBUlQgPSAnU1RBUlQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25RdWVyeSB7XG4gICAgZXZlbnQ6IENoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25RdWVyeUV2ZW50O1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL2RvbmF0aW9uLnB5LyNsaW5lcy0zNFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2hlY2tJZkNhbkF0dGVtcHREb25hdGlvblJlc3BvbnNlIHtcbiAgICBjYW5fYXR0ZW1wdDogYm9vbGVhbjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9kb25hdGlvbi5weS8jbGluZXMtMTg0XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVBbm9ueW1vdXNEb25hdGlvbkJvZHkge1xuICAgIGFtb3VudDogbnVtYmVyO1xuICAgIGVtYWlsOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvcGF5bWVudC5weS8jbGluZXMtOVxuICovXG5cbmV4cG9ydCBlbnVtIENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZUFub255bW91c0RvbmF0aW9uUmVzcG9uc2VQcm9kdWN0VHlwZSB7XG4gICAgRE9OQVRJT04gPSAnRE9OQVRJT04nLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWScsXG4gICAgU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9ZRUFSTFknLFxufVxuXG5leHBvcnQgZW51bSBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlU3RhdHVzIHtcbiAgICBDQU5DRUxFRCA9ICdDQU5DRUxFRCcsXG4gICAgQ09NUExFVEVEID0gJ0NPTVBMRVRFRCcsXG4gICAgTkVXID0gJ05FVycsXG4gICAgUEVORElORyA9ICdQRU5ESU5HJyxcbiAgICBSRUpFQ1RFRCA9ICdSRUpFQ1RFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZSB7XG4gICAgYW1vdW50OiBzdHJpbmc7XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgY3VycmVuY3k/OiBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlQ3VycmVuY3k7XG4gICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICBwcmljZT86IHN0cmluZztcbiAgICAgICAgcHJvZHVjdF90eXBlOiBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgfTtcbiAgICBzdGF0dXM/OiBDcmVhdGVBbm9ueW1vdXNEb25hdGlvblJlc3BvbnNlU3RhdHVzO1xuICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvZG9uYXRpb24ucHkvI2xpbmVzLTE4NFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JlYXRlRG9uYXRpb25Cb2R5IHtcbiAgICBhbW91bnQ6IG51bWJlcjtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9zZXJpYWxpemVycy9wYXltZW50LnB5LyNsaW5lcy05XG4gKi9cblxuZXhwb3J0IGVudW0gQ3JlYXRlRG9uYXRpb25SZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlRG9uYXRpb25SZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZURvbmF0aW9uUmVzcG9uc2VTdGF0dXMge1xuICAgIENBTkNFTEVEID0gJ0NBTkNFTEVEJyxcbiAgICBDT01QTEVURUQgPSAnQ09NUExFVEVEJyxcbiAgICBORVcgPSAnTkVXJyxcbiAgICBQRU5ESU5HID0gJ1BFTkRJTkcnLFxuICAgIFJFSkVDVEVEID0gJ1JFSkVDVEVEJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVEb25hdGlvblJlc3BvbnNlIHtcbiAgICBhbW91bnQ6IHN0cmluZztcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGRpc3BsYXlfYW1vdW50OiBzdHJpbmc7XG4gICAgcHJvZHVjdDoge1xuICAgICAgICBjdXJyZW5jeT86IENyZWF0ZURvbmF0aW9uUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgZGlzcGxheV9wcmljZTogc3RyaW5nO1xuICAgICAgICBuYW1lOiBzdHJpbmc7XG4gICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0X3R5cGU6IENyZWF0ZURvbmF0aW9uUmVzcG9uc2VQcm9kdWN0VHlwZTtcbiAgICB9O1xuICAgIHN0YXR1cz86IENyZWF0ZURvbmF0aW9uUmVzcG9uc2VTdGF0dXM7XG4gICAgc3RhdHVzX2xlZGdlcj86IE9iamVjdDtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9kb25hdGlvbi5weS8jbGluZXMtMTg0XG4gKi9cblxuZXhwb3J0IGVudW0gQ3JlYXRlRG9uYXRpb25hdHRlbXB0Qm9keUV2ZW50IHtcbiAgICBDTE9TRSA9ICdDTE9TRScsXG4gICAgUkVDQUxMID0gJ1JFQ0FMTCcsXG4gICAgU1RBUlQgPSAnU1RBUlQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZURvbmF0aW9uYXR0ZW1wdEJvZHkge1xuICAgIGV2ZW50OiBDcmVhdGVEb25hdGlvbmF0dGVtcHRCb2R5RXZlbnQ7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvZG9uYXRpb24ucHkvI2xpbmVzLThcbiAqL1xuXG5leHBvcnQgZW51bSBDcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZUV2ZW50IHtcbiAgICBDTE9TRSA9ICdDTE9TRScsXG4gICAgUkVDQUxMID0gJ1JFQ0FMTCcsXG4gICAgU1RBUlQgPSAnU1RBUlQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZURvbmF0aW9uYXR0ZW1wdFJlc3BvbnNlIHtcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGV2ZW50OiBDcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZUV2ZW50O1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRXh0ZXJuYWwgQXBwcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9leHRlcm5hbF9hcHBzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBFeHRlcm5hbEFwcHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQXV0aG9yaXplIGEgZ2l2ZW4gZXh0ZXJuYWwgYXBwIHRva2VuXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQ2FuIGJlIGNhbGxlZCBieSB0aGUgQVBJIEdhdGV3YXkgaW4gb3JkZXIgdG8gYXV0aG9yaXplIGV2ZXJ5IHJlcXVlc3QgdXNpbmcgcHJvdmlkZWQgdG9rZW4uIEl0IG11c3QgYmUgdXNlZCBvbmx5IGZvciBleHRlcm5hbCBhcHAgdG9rZW5zLCB3aGljaCBhcmUgdXNlZCBieSB0aGUgZXh0ZXJuYWwgYXBwcyB0byBtYWtlIGNhbGxzIG9uIGJlaGFsZiBvZiBhIGdpdmVuIHVzZXIuXG4gICAgICovXG4gICAgcHVibGljIGF1dGhvcml6ZUV4dGVybmFsQXBwQXV0aFRva2VuKCk6IE9ic2VydmFibGU8WC5BdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5BdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPignL2V4dGVybmFsL2F1dGhfdG9rZW5zL2F1dGhvcml6ZS8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAvLyAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBFeHRlcm5hbCBBcHAgQ29uZmlndXJhdGlvblxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlblJlc3BvbnNlPignL2V4dGVybmFsL2F1dGhfdG9rZW5zLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBFeHRlcm5hbCBBcHAgY29uZmlndXJhdGlvblxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRXh0ZXJuYWxhcHBjb25mKHBhcmFtczogWC5SZWFkRXh0ZXJuYWxhcHBjb25mUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4oJy9leHRlcm5hbC9hcHBzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRXh0ZXJuYWxhcHBjb25mMihwYXJhbXM6IFguUmVhZEV4dGVybmFsYXBwY29uZlF1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRFeHRlcm5hbGFwcGNvbmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPignL2V4dGVybmFsL2FwcHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZvY3VzIFJlY29yZHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZm9jdXNfcmVjb3Jkcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRm9jdXNSZWNvcmRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBGb2N1cyBSZWNvcmRcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRm9jdXNyZWNvcmQoYm9keTogWC5DcmVhdGVGb2N1c3JlY29yZEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRm9jdXNyZWNvcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRm9jdXNyZWNvcmRSZXNwb25zZT4oJy9mb2N1c19yZWNvcmRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBGb2N1cyBSZWNvcmQgU3VtbWFyeVxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRm9jdXNSZWNvcmRTdW1tYXJ5KCk6IERhdGFTdGF0ZTxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPignL2ZvY3VzX3JlY29yZHMvc3VtbWFyeS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRGb2N1c1JlY29yZFN1bW1hcnkyKCk6IE9ic2VydmFibGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4oJy9mb2N1c19yZWNvcmRzL3N1bW1hcnkvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBGcmFnbWVudCBIYXNodGFncyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9mcmFnbWVudF9oYXNodGFncy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRnJhZ21lbnRIYXNodGFnc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IEhhc2h0YWdzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBIYXNodGFnc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEZyYWdtZW50SGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvaGFzaHRhZ3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL2hhc2h0YWdzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgSGFzaHRhZ3NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBIYXNodGFnc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvaGFzaHRhZ3MvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvaGFzaHRhZ3MvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRnJhZ21lbnQgV29yZHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vZnJhZ21lbnRfd29yZHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZyYWdtZW50V29yZHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBXb3Jkc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgV29yZHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudFdvcmRzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50V29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3dvcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEZyYWdtZW50V29yZHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50V29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFdvcmRzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgV29yZHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3dvcmRzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3dvcmRzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZyYWdtZW50cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9mcmFnbWVudHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZyYWdtZW50c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZnJhZ21lbnRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdmcmFnbWVudHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgUmVtb3RlIEZyYWdtZW50c1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2ZyYWdtZW50cycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50czIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdmcmFnbWVudHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZyYWdtZW50KCk6IE9ic2VydmFibGU8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPignL2ZyYWdtZW50cy8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZWxldGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRGVsZXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNZXJnZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBNZXJnZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgbWVyZ2VGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguTWVyZ2VGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5NZXJnZUZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vbWVyZ2UvYCwge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHVibGlzaCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBQdWJsaXNoIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBwdWJsaXNoRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlB1Ymxpc2hGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlB1Ymxpc2hGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L3B1Ymxpc2gvYCwge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRnJhZ21lbnQyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEZyYWdtZW50IERpZmZcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIEZyYWdtZW50IERpZmZcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50RGlmZihmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9kaWZmL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50RGlmZjIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L2RpZmYvYCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBGcmFnbWVudCBTYW1wbGVcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIEZyYWdtZW50IFNhbXBsZVxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRnJhZ21lbnRTYW1wbGUoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L3NhbXBsZS9gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRnJhZ21lbnRTYW1wbGUyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vc2FtcGxlL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVGcmFnbWVudChmcmFnbWVudElkOiBhbnksIGJvZHk6IFguVXBkYXRlRnJhZ21lbnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBHZW9tZXRyaWVzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2dlb21ldHJpZXMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEdlb21ldHJpZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBHZW9tZXRyaWVzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBHZW9tZXRyaWVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEdlb21ldHJpZXMocGFyYW1zOiBYLkJ1bGtSZWFkR2VvbWV0cmllc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRHZW9tZXRyaWVzUmVzcG9uc2VFbnRpdHlbXT4oJy9ncmlkL2dlb21ldHJpZXMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZ2VvbWV0cmllcycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkR2VvbWV0cmllczIocGFyYW1zOiBYLkJ1bGtSZWFkR2VvbWV0cmllc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+KCcvZ3JpZC9nZW9tZXRyaWVzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2dlb21ldHJpZXMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQnVsayBVcGRhdGUgR2VvbWV0cmllc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSBpbiBhIEJ1bGsgbGlzdCBvZiBHZW9tZXRyaWVzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrVXBkYXRlR2VvbWV0cmllcyhib2R5OiBYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzQm9keSk6IE9ic2VydmFibGU8WC5CdWxrVXBkYXRlR2VvbWV0cmllc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLkJ1bGtVcGRhdGVHZW9tZXRyaWVzUmVzcG9uc2U+KCcvZ3JpZC9nZW9tZXRyaWVzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBHZW9tZXRyeSBieSBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBhIEdlb21ldHJ5IGVudGl0eSBnaXZlbiB0aGUgaWQgb2YgQ2FyZCB3aGljaCBpcyB0aGUgcGFyZW50IG9mIHRoZSBHZW9tZXRyeSBlbnRpdHkuXG4gICAgICovXG4gICAgcHVibGljIHJlYWRHZW9tZXRyeUJ5Q2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkR2VvbWV0cnlCeUNhcmRSZXNwb25zZT4oYC9ncmlkL2dlb21ldHJpZXMvYnlfY2FyZC8ke2NhcmRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRHZW9tZXRyeUJ5Q2FyZDIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEdlb21ldHJ5QnlDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPihgL2dyaWQvZ2VvbWV0cmllcy9ieV9jYXJkLyR7Y2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgR3JhcGhcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZW5kZXIgYW5kIHJlYWQgR3JhcGggbWFkZSBvdXQgb2YgYWxsIENhcmRzIGFuZCBMaW5rcyBiZWxvbmdpbmcgdG8gYSBnaXZlbiB1c2VyLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkR3JhcGgocGFyYW1zOiBYLlJlYWRHcmFwaFF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEdyYXBoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRHcmFwaFJlc3BvbnNlPignL2dyaWQvZ3JhcGhzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkR3JhcGgyKHBhcmFtczogWC5SZWFkR3JhcGhRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkR3JhcGhSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEdyYXBoUmVzcG9uc2U+KCcvZ3JpZC9ncmFwaHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEhhc2h0YWdzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2hhc2h0YWdzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBIYXNodGFnc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IEhhc2h0YWdzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gbGlzdCBhIHNlcmllcyBvZiBIYXNodGFnIGluc3RhbmNlcy4gSXQgYWNjZXB0cyB2YXJpb3VzIHF1ZXJ5IHBhcmFtZXRlcnMgc3VjaCBhczogLSBgbGltaXRgIC0gYG9mZnNldGAgLSBgZmlyc3RfY2hhcmFjdGVyYFxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZEhhc2h0YWdzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+KCcvaGFzaHRhZ3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnaGFzaHRhZ3MnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9oYXNodGFncy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdoYXNodGFncycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGluZyBhIHNpbmdsZSBIYXNodGFnXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY3JlYXRlIGEgc2luZ2xlIEhhc2h0YWcgaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUhhc2h0YWcoYm9keTogWC5DcmVhdGVIYXNodGFnQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVIYXNodGFnUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUhhc2h0YWdSZXNwb25zZT4oJy9oYXNodGFncy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92aW5nIGEgc2luZ2xlIEhhc2h0YWdcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBkZXRhY2ggYSBzaW5nbGUgSGFzaHRhZyBpbnN0YW5jZSBmcm9tIGEgbGlzdCBjYXJkcyBnaXZlbiBieSBgY2FyZF9pZHNgLlxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVIYXNodGFnKGhhc2h0YWdJZDogYW55LCBwYXJhbXM6IFguRGVsZXRlSGFzaHRhZ1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVIYXNodGFnUmVzcG9uc2U+KGAvaGFzaHRhZ3MvJHtoYXNodGFnSWR9YCwgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgSGFzaHRhZ3MgVE9DXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gbGlzdCBIYXNodGFncyBUYWJsZSBvZiBDb250ZW50cyBtYWRlIG91dCBvZiBIYXNodGFncy4gTm90ZTogQ3VycmVudGx5IHRoaXMgZW5kcG9pbnQgcmV0dXJucyBvbmx5IGEgZmxhdCBsaXN0IG9mIGhhc2h0YWdzIHdpdGggdGhlIGNvdW50IG9mIENhcmRzIHdpdGggd2hpY2ggdGhleSdyZSBhdHRhY2hlZCB0by4gSW4gdGhlIGZ1dHVyZSB0aG91Z2ggb25lIGNvdWxkIHByb3Bvc2UgYSBtZWNoYW5pc20gd2hpY2ggY291bGQgY2FsY3VsYXRlIGhpZXJhcmNoeSBiZXR3ZWVuIHRob3NlIGhhc2h0YWdzIChwYXJlbnQgLSBjaGlsZCByZWxhdGlvbnNoaXBzKSBhbmQgb3JkZXJpbmcgYmFzZWQgb24gdGhlIGtub3dsZWRnZSBncmlkIHRvcG9sb2d5LiBJdCBhY2NlcHRzIHZhcmlvdXMgcXVlcnkgcGFyYW1ldGVycyBzdWNoIGFzOiAtIGBsaW1pdGAgLSBgb2Zmc2V0YFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkSGFzaHRhZ3NUb2MocGFyYW1zOiBYLlJlYWRIYXNodGFnc1RvY1F1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPignL2hhc2h0YWdzL3RvYycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkSGFzaHRhZ3NUb2MyKHBhcmFtczogWC5SZWFkSGFzaHRhZ3NUb2NRdWVyeSk6IE9ic2VydmFibGU8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+KCcvaGFzaHRhZ3MvdG9jJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGluZyBhIHNpbmdsZSBIYXNodGFnXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gdXBkYXRlIGEgc2luZ2xlIEhhc2h0YWcgaW5zdGFuY2Ugd2l0aCBhIGxpc3Qgb2YgYGNhcmRfaWRzYCB0byB3aGljaCBpdCBzaG91bGQgZ2V0IGF0dGFjaGVkIHRvLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVIYXNodGFnKGhhc2h0YWdJZDogYW55LCBib2R5OiBYLlVwZGF0ZUhhc2h0YWdCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVIYXNodGFnUmVzcG9uc2U+KGAvaGFzaHRhZ3MvJHtoYXNodGFnSWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEludGVybmFsIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ludGVybmFsLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBJbnRlcm5hbERvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDbGVhciBhbGwgRW50cmllcyBmb3IgYSBnaXZlbiBVc2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogSW50ZXJuYWwgdmlldyBlbmFibGluZyBvbmUgdG8gY2xlYW4gdXAgYWxsIGRhdGFiYXNlIGVudHJpZXMgZm9yIGEgc3BlY2lmaWMgYHVzZXJfaWRgLiBJdCBtdXN0IGJlIG9mIHRoZSB1dG1vc3QgaW1wb3J0YW5jZSB0aGF0IHRoaXMgZW5kcG9pbnQgd291bGQgbm90IGJlIGF2YWlsYWJsZSBvbiB0aGUgcHJvZHVjdGlvbiBzeXN0ZW0uXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZUVudHJpZXNGb3JVc2VyKHVzZXJJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUVudHJpZXNGb3JVc2VyUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguRGVsZXRlRW50cmllc0ZvclVzZXJSZXNwb25zZT4oYC9yZXNldC8ke3VzZXJJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogSW52b2ljZSBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9pbnZvaWNlcy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgSW52b2ljZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBhbGwgSW52b2ljZXMgYmVsb25naW5nIHRvIGEgZ2l2ZW4gdXNlclxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgdGhlIHRoZSBVc2VyIHRvIGxpc3QgYWxsIG9mIHRoZSBJbnZvaWNlcyB3aGljaCB3ZXJlIGdlbmVyYXRlZCBmb3IgaGlzIERvbmF0aW9ucyBvciBTdWJzY3JpcHRpb24gcGF5bWVudHMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkSW52b2ljZXMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUVudGl0eVtdPignL3BheW1lbnRzL2ludm9pY2VzLycsIHsgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRJbnZvaWNlczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXltZW50cy9pbnZvaWNlcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYWxjdWxhdGUgZGVidCBmb3IgYSBnaXZlbiB1c2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogQ2FsY3VsYXRlIGRlYnQgZm9yIGEgZ2l2ZW4gdXNlciBieSBzZWFyY2hpbmcgZm9yIHRoZSBsYXRlc3QgdW5wYWlkIGludm9pY2UuIEl0IHJldHVybnMgcGF5bWVudCB0b2tlbiB3aGljaCBjYW4gYmUgdXNlZCBpbiB0aGUgUEFJRF9XSVRIX0RFRkFVTFRfUEFZTUVOVF9DQVJEIGNvbW1hbmRcbiAgICAgKi9cbiAgICBwdWJsaWMgY2FsY3VsYXRlRGVidCgpOiBEYXRhU3RhdGU8WC5DYWxjdWxhdGVEZWJ0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4oJy9wYXltZW50cy9pbnZvaWNlcy9kZWJ0LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgY2FsY3VsYXRlRGVidDIoKTogT2JzZXJ2YWJsZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQ2FsY3VsYXRlRGVidFJlc3BvbnNlPignL3BheW1lbnRzL2ludm9pY2VzL2RlYnQvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBJbnZvaWNlIE1hbmFnZW1lbnQgRG9tYWluIE1vZGVsc1xuICovXG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvaW52b2ljZS5weS8jbGluZXMtNTNcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VDdXJyZW5jeSB7XG4gICAgUExOID0gJ1BMTicsXG59XG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBhbW91bnQ6IHN0cmluZztcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGN1cnJlbmN5Pzogc3RyaW5nO1xuICAgIGRpc3BsYXlfYW1vdW50OiBzdHJpbmc7XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgaXNfZXh0ZW5zaW9uPzogYm9vbGVhbjtcbiAgICBwYWlkX3RpbGxfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgcHJvZHVjdDoge1xuICAgICAgICBjdXJyZW5jeT86IEJ1bGtSZWFkSW52b2ljZXNSZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3RfdHlwZTogQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgfTtcbiAgICBzdXJwbHVzX2Ftb3VudD86IHN0cmluZztcbiAgICBzdXJwbHVzX2N1cnJlbmN5Pzogc3RyaW5nO1xuICAgIHZhbGlkX3RpbGxfdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRJbnZvaWNlc1Jlc3BvbnNlIHtcbiAgICBkYXRhOiBCdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9pbnZvaWNlLnB5LyNsaW5lcy01MVxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2FsY3VsYXRlRGVidFJlc3BvbnNlIHtcbiAgICBhdF9fY29tbWFuZHM6IE9iamVjdDtcbiAgICBjdXJyZW5jeTogc3RyaW5nO1xuICAgIGRpc3BsYXlfb3dlczogc3RyaW5nO1xuICAgIG93ZXM6IG51bWJlcjtcbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIExpbmtzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2xpbmtzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBMaW5rc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgTGlua1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbW92ZSBhIExpbmsgYmV0d2VlbiB0d28gY2FyZHMuXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZUxpbmsoZnJvbUNhcmRJZDogYW55LCB0b0NhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUxpbmtSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVMaW5rUmVzcG9uc2U+KGAvZ3JpZC9saW5rcy8ke2Zyb21DYXJkSWR9LyR7dG9DYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIG9yIENyZWF0ZSBMaW5rXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBvciBDcmVhdGUgYSBMaW5rIGJldHdlZW4gdHdvIGNhcmRzLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkT3JDcmVhdGVMaW5rKGJvZHk6IFguUmVhZE9yQ3JlYXRlTGlua0JvZHkpOiBPYnNlcnZhYmxlPFguUmVhZE9yQ3JlYXRlTGlua1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5SZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2U+KCcvZ3JpZC9saW5rcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogTGlua3MgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy9iOGRlYzNjZjEzZDE4OTcxMDkyMjA3ODdmOTk1NTQ2NTU4ZGU0NzdkL3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBEZWxldGVMaW5rUmVzcG9uc2Uge31cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy9iOGRlYzNjZjEzZDE4OTcxMDkyMjA3ODdmOTk1NTQ2NTU4ZGU0NzdkL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL2dyaWQvdmlld3MucHkvI2xpbmVzLTQ3XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBSZWFkT3JDcmVhdGVMaW5rQm9keSB7XG4gICAgZnJvbV9jYXJkX2lkOiBudW1iZXI7XG4gICAgdG9fY2FyZF9pZDogbnVtYmVyO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjL2I4ZGVjM2NmMTNkMTg5NzEwOTIyMDc4N2Y5OTU1NDY1NThkZTQ3N2QvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvZ3JpZC9zZXJpYWxpemVycy5weS8jbGluZXMtOFxuICovXG5cbmV4cG9ydCBlbnVtIFJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZUtpbmQge1xuICAgIENBUkQgPSAnQ0FSRCcsXG4gICAgRlJBR01FTlQgPSAnRlJBR01FTlQnLFxuICAgIEhBU0hUQUcgPSAnSEFTSFRBRycsXG4gICAgUEFUSCA9ICdQQVRIJyxcbiAgICBURVJNID0gJ1RFUk0nLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIFJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZSB7XG4gICAgYXV0aG9yX2lkPzogYW55O1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZnJvbV9jYXJkX2lkPzogYW55O1xuICAgIGlkPzogbnVtYmVyO1xuICAgIGtpbmQ6IFJlYWRPckNyZWF0ZUxpbmtSZXNwb25zZUtpbmQ7XG4gICAgcmVmZXJlbmNlX2lkOiBudW1iZXI7XG4gICAgdG9fY2FyZF9pZD86IGFueTtcbiAgICB2YWx1ZTogbnVtYmVyO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogTWVkaWFJdGVtcyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9tZWRpYWl0ZW1zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBNZWRpYWl0ZW1zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgTWVkaWFJdGVtc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgTWVkaWFJdGVtc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZE1lZGlhaXRlbXMocGFyYW1zOiBYLkJ1bGtSZWFkTWVkaWFpdGVtc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRNZWRpYWl0ZW1zUmVzcG9uc2VFbnRpdHlbXT4oJy9tZWRpYWl0ZW1zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZE1lZGlhaXRlbXMyKHBhcmFtczogWC5CdWxrUmVhZE1lZGlhaXRlbXNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPignL21lZGlhaXRlbXMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgTWVkaWFJdGVtXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVtb3ZlIE1lZGlhSXRlbSBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgZGVsZXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnksIHBhcmFtczogWC5EZWxldGVNZWRpYWl0ZW1RdWVyeSk6IE9ic2VydmFibGU8WC5EZWxldGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVNZWRpYWl0ZW1SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9YCwgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgTWVkaWFJdGVtXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBNZWRpYUl0ZW1cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55KTogRGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy8ke21lZGlhaXRlbUlkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbTIobWVkaWFpdGVtSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRNZWRpYWl0ZW1SZXNwb25zZT4oYC9tZWRpYWl0ZW1zLyR7bWVkaWFpdGVtSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBCeSBQcm9jZXNzIElkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogUmVhZCBNZWRpYUl0ZW0gYnkgUHJvY2VzcyBJZFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWQocHJvY2Vzc0lkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy9ieV9wcm9jZXNzLyR7cHJvY2Vzc0lkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkMihwcm9jZXNzSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+KGAvbWVkaWFpdGVtcy9ieV9wcm9jZXNzLyR7cHJvY2Vzc0lkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgb3IgQ3JlYXRlIE1lZGlhSXRlbVxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgb3IgQ3JlYXRlIE1lZGlhSXRlbSBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZE9yQ3JlYXRlTWVkaWFpdGVtKGJvZHk6IFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtQm9keSk6IE9ic2VydmFibGU8WC5SZWFkT3JDcmVhdGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguUmVhZE9yQ3JlYXRlTWVkaWFpdGVtUmVzcG9uc2U+KCcvbWVkaWFpdGVtcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBNZWRpYUl0ZW1cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgTWVkaWFJdGVtIGluc3RhbmNlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVNZWRpYWl0ZW0obWVkaWFpdGVtSWQ6IGFueSwgYm9keTogWC5VcGRhdGVNZWRpYWl0ZW1Cb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZU1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZU1lZGlhaXRlbVJlc3BvbnNlPihgL21lZGlhaXRlbXMvJHttZWRpYWl0ZW1JZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSBNZWRpYUl0ZW0gUmVwcmVzZW50YXRpb25cbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBVcGRhdGUgZ2l2ZW4gTWVkaWFJdGVtIHdpdGggb25seSB0aGUgZmllbGRzIHdoaWNoIGFyZSBkZWNpZGVkIGV4dGVybmFsbHkgKHVzaW5nIGV4dGVybmFsIHNlcnZpY2VzKS4gRmllbGRzIGxpa2U6IC0gYHdlYl9yZXByZXNlbnRhdGlvbnNgIC0gYHRodW1ibmFpbF91cmlgIC0gYG1ldGFgIC0gYHRleHRgIEFsbCBvZiB0aG9zZSBmaWVsZHMgYXJlIGNvbXB1dGVkIGluIHNtYXJ0ZXIgd2F5IGluIG9yZGVyIHRvIG1ha2UgdGhlIE1lZGlhSXRlbSB3YXkgYmV0dGVyIGluIGEgc2VtYW50aWMgc2Vuc2UuIFRob3NlIGZpZWxkcyBhcmUgcGVyY2VpdmVkIGFzIHRoZSBgcmVwcmVzZW50YXRpb25gIG9mIGEgZ2l2ZW4gTWVkaWFJdGVtIHNpbmNlIHRoZXkgY29udGFpbnMgaW5mb3JtYXRpb24gYWJvdXQgaG93IHRvIGRpc3BsYXkgYSBnaXZlbiBNZWRpYUl0ZW0sIGhvdyB0byB1bmRlcnN0YW5kIGl0IGV0Yy4gSXQgZ29lcyBiZXlvbmQgdGhlIHNpbXBsZSBhYnN0cmFjdCBkYXRhIG9yaWVudGVkIHJlcHJlc2VudGF0aW9uICh1cmksIGV4dGVuc2lvbiBldGMuKS5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb24obWVkaWFpdGVtSWQ6IGFueSwgYm9keTogWC5VcGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvblJlc3BvbnNlPihgL21lZGlhaXRlbXMvJHttZWRpYWl0ZW1JZH0vcmVwcmVzZW50YXRpb24vYCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIE5vdGlmaWNhdGlvbiBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9ub3RpZmljYXRpb25zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBOb3RpZmljYXRpb25zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIEFja25vd2xlZGdlIE5vdGlmaWNhdGlvblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEFja25vd2xlZGdlIE5vdGlmaWNhdGlvblxuICAgICAqL1xuICAgIHB1YmxpYyBhY2tub3dsZWRnZU5vdGlmaWNhdGlvbihub3RpZmljYXRpb25JZDogYW55KTogT2JzZXJ2YWJsZTxYLkFja25vd2xlZGdlTm90aWZpY2F0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguQWNrbm93bGVkZ2VOb3RpZmljYXRpb25SZXNwb25zZT4oYC9ub3RpZmljYXRpb25zLyR7bm90aWZpY2F0aW9uSWR9L2Fja25vd2xlZGdlL2AsIHt9LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpc3QgTm90aWZpY2F0aW9uc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgTm90aWZpY2F0aW9uc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZE5vdGlmaWNhdGlvbnMocGFyYW1zOiBYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4oJy9ub3RpZmljYXRpb25zLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZE5vdGlmaWNhdGlvbnMyKHBhcmFtczogWC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdPignL25vdGlmaWNhdGlvbnMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIE5vdGlmaWNhdGlvbiBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZnJhZ21lbnQtc2VydmljZS9zcmMvYjAyM2FkNWRhMTUwMjc2ODMwMjg2MDljMTQwMjYwYjBhMTgwODQ1Mi8udmVudi9zcmMvbGlseS9saWx5L2Jhc2Uvc2VyaWFsaXplcnMucHkvI2xpbmVzLTE1OFxuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgQWNrbm93bGVkZ2VOb3RpZmljYXRpb25SZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZnJhZ21lbnQtc2VydmljZS9zcmMvYjAyM2FkNWRhMTUwMjc2ODMwMjg2MDljMTQwMjYwYjBhMTgwODQ1Mi9jb3NwaGVyZV9mcmFnbWVudF9zZXJ2aWNlL25vdGlmaWNhdGlvbi92aWV3cy5weS8jbGluZXMtNzdcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkTm90aWZpY2F0aW9uc1F1ZXJ5IHtcbiAgICBhY2tub3dsZWRnZWQ/OiBib29sZWFuO1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wX19ndD86IG51bWJlcjtcbiAgICBsaW1pdD86IG51bWJlcjtcbiAgICBvZmZzZXQ/OiBudW1iZXI7XG4gICAgdXBkYXRlZF90aW1lc3RhbXBfX2d0PzogbnVtYmVyO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZnJhZ21lbnQtc2VydmljZS9zcmMvYjAyM2FkNWRhMTUwMjc2ODMwMjg2MDljMTQwMjYwYjBhMTgwODQ1Mi9jb3NwaGVyZV9mcmFnbWVudF9zZXJ2aWNlL25vdGlmaWNhdGlvbi9zZXJpYWxpemVycy5weS8jbGluZXMtNDZcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUtpbmQge1xuICAgIEZSQUdNRU5UX1VQREFURSA9ICdGUkFHTUVOVF9VUERBVEUnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBhY2tub3dsZWRnZWQ6IGJvb2xlYW47XG4gICAgY3JlYXRlZF90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBpZD86IG51bWJlcjtcbiAgICBraW5kOiBCdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUtpbmQ7XG4gICAgcGF5bG9hZDogT2JqZWN0O1xuICAgIHVwZGF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2Uge1xuICAgIGRhdGE6IEJ1bGtSZWFkTm90aWZpY2F0aW9uc1Jlc3BvbnNlRW50aXR5W107XG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBQYXRocyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9wYXRocy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUGF0aHNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogRGVsZXRlIFBhdGhzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5kcG9pbnQgZm9yIERlbGV0aW5nIG11bHRpcGxlIFBhdGhzLlxuICAgICAqL1xuICAgIHB1YmxpYyBidWxrRGVsZXRlUGF0aHMocGFyYW1zOiBYLkJ1bGtEZWxldGVQYXRoc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtEZWxldGVQYXRoc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkJ1bGtEZWxldGVQYXRoc1Jlc3BvbnNlPignL3BhdGhzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFBhdGhzXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogTGlzdCBhbGwgdXNlcidzIFBhdGhzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUGF0aHMocGFyYW1zOiBYLkJ1bGtSZWFkUGF0aHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4oJy9wYXRocy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdwYXRocycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUGF0aHMyKHBhcmFtczogWC5CdWxrUmVhZFBhdGhzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUGF0aHNSZXNwb25zZUVudGl0eVtdPignL3BhdGhzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ3BhdGhzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBQYXRoXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5kcG9pbnQgZm9yIENyZWF0aW5nIFBhdGguXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZVBhdGgoYm9keTogWC5DcmVhdGVQYXRoQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZVBhdGhSZXNwb25zZT4oJy9wYXRocy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgUGF0aFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgc2luZ2xlIFBhdGhcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZFBhdGgocGF0aElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkUGF0aFJlc3BvbnNlPihgL3BhdGhzLyR7cGF0aElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZFBhdGgyKHBhdGhJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRQYXRoUmVzcG9uc2U+KGAvcGF0aHMvJHtwYXRoSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIFBhdGhcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmRwb2ludCBmb3IgVXBkYXRpbmcgUGF0aC5cbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlUGF0aChwYXRoSWQ6IGFueSwgYm9keTogWC5VcGRhdGVQYXRoQm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVQYXRoUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlUGF0aFJlc3BvbnNlPihgL3BhdGhzLyR7cGF0aElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBQYXltZW50IENhcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3BheW1lbnRfY2FyZHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFBheW1lbnRDYXJkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBNYXJrIGEgZ2l2ZW4gUGF5bWVudCBDYXJkIGFzIGEgZGVmYXVsdCBvbmVcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIHRoZSB0aGUgVXNlciB0byBtYXJrIGEgc3BlY2lmaWMgUGF5bWVudCBDYXJkIGFzIGEgZGVmYXVsdCBvbmUsIG1lYW5pbmcgdGhhdCBpdCB3aWxsIGJlIHVzZWQgZm9yIGFsbCB1cGNvbWluZyBwYXltZW50cy4gTWFya2luZyBQYXltZW50IENhcmQgYXMgYSBkZWZhdWx0IG9uZSBhdXRvbWF0aWNhbGx5IGxlYWRzIHRvIHRoZSB1bm1hcmtpbmcgb2YgYW55IFBheW1lbnQgQ2FyZCB3aGljaCB3YXMgZGVmYXVsdCBvbmUgYmVmb3JlIHRoZSBpbnZvY2F0aW9uIG9mIHRoZSBjb21tYW5kLlxuICAgICAqL1xuICAgIHB1YmxpYyBhc0RlZmF1bHRNYXJrUGF5bWVudGNhcmQocGF5bWVudENhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLkFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZFJlc3BvbnNlPihgL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvJHtwYXltZW50Q2FyZElkfS9tYXJrX2FzX2RlZmF1bHQvYCwge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBhbGwgUGF5bWVudCBDYXJkcyBiZWxvbmdpbmcgdG8gYSBnaXZlbiB1c2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gbGlzdCBhbGwgb2YgdGhlIFBheW1lbnQgQ2FyZHMgd2hpY2ggd2VyZSBhZGRlZCBieSBoaW0gLyBoZXIuIEFtb25nIGFsbCByZXR1cm5lZCBQYXltZW50IENhcmRzIHRoZXJlIG11c3QgYmUgb25lIGFuZCBvbmx5IG9uZSB3aGljaCBpcyBtYXJrZWQgYXMgKipkZWZhdWx0KiouXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUGF5bWVudGNhcmRzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdPignL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFBheW1lbnRjYXJkczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdPignL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvJywgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGEgUGF5bWVudCBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gYWRkIG5ldyBQYXltZW50IENhcmQsIHdoaWNoIGNvdWxkIGJlIG5lZWRlZCBpbiBjYXNlcyB3aGVuIHRoZSBVc2VyIHdvdWxkIGxpa2UgdG8gcmVwbGFjZSBleGlzdGluZyBQYXltZW50IENhcmQgYmVjYXVzZTogLSBpdCBleHBpcmVkIC0gaXMgZW1wdHkgLSB0aGUgVXNlciBwcmVmZXJzIGFub3RoZXIgb25lIHRvIGJlIHVzZWQgZnJvbSBub3cgb24uIFVzaW5nIHRoZSBvcHRpb25hbCBgbWFya19hc19kZWZhdWx0YCBmaWVsZCBvbmUgY2FuIG1hcmsganVzdCBjcmVhdGVkIFBheW1lbnQgQ2FyZCBhcyB0aGUgZGVmYXVsdCBvbmUuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZVBheW1lbnRjYXJkKGJvZHk6IFguQ3JlYXRlUGF5bWVudGNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2U+KCcvcGF5bWVudHMvcGF5bWVudF9jYXJkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlbW92ZSBhIGdpdmVuIFBheW1lbnQgQ2FyZCBiZWxvbmdpbmcgdG8gYSBnaXZlbiB1c2VyXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyB0aGUgdGhlIFVzZXIgdG8gcmVtb3ZlIGEgc3BlY2lmaWMgUGF5bWVudCBDYXJkIHdoaWNoIHdlcmUgYWRkZWQgYnkgaGltIC8gaGVyLiBQYXltZW50IENhcmQgY2FuIGJlIHJlbW92ZWQgb25seSBpZiBpdCdzIG5vdCBhIGRlZmF1bHQgb25lLlxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVQYXltZW50Y2FyZChwYXltZW50Q2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlUGF5bWVudGNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVQYXltZW50Y2FyZFJlc3BvbnNlPihgL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvJHtwYXltZW50Q2FyZElkfWAsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUGF5IHVzaW5nIHRoZSBkZWZhdWx0IFBheW1lbnQgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVzZXIgaXMgYWxsb3dlZCBvbmx5IHRvIHBlcmZvcm0gcGF5bWVudHMgYWdhaW5zdCBoZXIgZGVmYXVsdCBQYXltZW50IENhcmQuIEluIG90aGVyIHdvcmRzIG9uIG9yZGVyIHRvIHVzZSBhIGdpdmVuIFBheW1lbnQgQ2FyZCBvbmUgaGFzIHRvIG1hcmsgaXMgYXMgZGVmYXVsdC4gQWxzbyBvbmUgaXMgbm90IGFsbG93ZWQgdG8gcGVyZm9ybSBzdWNoIHBheW1lbnRzIGZyZWVseSBhbmQgdGhlcmVmb3JlIHdlIGV4cGVjdCB0byBnZXQgYSBgcGF5bWVudF90b2tlbmAgaW5zaWRlIHdoaWNoIGFub3RoZXIgcGllY2Ugb2Ygb3VyIHN5c3RlbSBlbmNvZGVkIGFsbG93ZWQgc3VtIHRvIGJlIHBhaWQuXG4gICAgICovXG4gICAgcHVibGljIHBheVdpdGhEZWZhdWx0UGF5bWVudENhcmQoYm9keTogWC5QYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkQm9keSk6IE9ic2VydmFibGU8WC5QYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLlBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZT4oJy9wYXltZW50cy9wYXltZW50X2NhcmRzL3BheV93aXRoX2RlZmF1bHQvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgYSBQYXltZW50IENhcmRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIHRoZSB0aGUgVXNlciB0byBhZGQgbmV3IFBheW1lbnQgQ2FyZCwgd2hpY2ggY291bGQgYmUgbmVlZGVkIGluIGNhc2VzIHdoZW4gdGhlIFVzZXIgd291bGQgbGlrZSB0byByZXBsYWNlIGV4aXN0aW5nIFBheW1lbnQgQ2FyZCBiZWNhdXNlOiAtIGl0IGV4cGlyZWQgLSBpcyBlbXB0eSAtIHRoZSBVc2VyIHByZWZlcnMgYW5vdGhlciBvbmUgdG8gYmUgdXNlZCBmcm9tIG5vdyBvblxuICAgICAqL1xuICAgIHB1YmxpYyByZW5kZXJQYXltZW50Q2FyZFdpZGdldCgpOiBEYXRhU3RhdGU8WC5SZW5kZXJQYXltZW50Q2FyZFdpZGdldFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZW5kZXJQYXltZW50Q2FyZFdpZGdldFJlc3BvbnNlPignL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvd2lkZ2V0LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVuZGVyUGF5bWVudENhcmRXaWRnZXQyKCk6IE9ic2VydmFibGU8WC5SZW5kZXJQYXltZW50Q2FyZFdpZGdldFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZW5kZXJQYXltZW50Q2FyZFdpZGdldFJlc3BvbnNlPignL3BheW1lbnRzL3BheW1lbnRfY2FyZHMvd2lkZ2V0LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUGF5bWVudCBDYXJkcyBNYW5hZ2VtZW50IERvbWFpbiBNb2RlbHNcbiAqL1xuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBBc0RlZmF1bHRNYXJrUGF5bWVudGNhcmRSZXNwb25zZSB7fVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3NlcmlhbGl6ZXJzL3BheW1lbnRfY2FyZC5weS8jbGluZXMtNzVcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlQ3VycmVuY3kge1xuICAgIFBMTiA9ICdQTE4nLFxufVxuXG5leHBvcnQgZW51bSBCdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZVN0YXR1cyB7XG4gICAgQ0FOQ0VMRUQgPSAnQ0FOQ0VMRUQnLFxuICAgIENPTVBMRVRFRCA9ICdDT01QTEVURUQnLFxuICAgIE5FVyA9ICdORVcnLFxuICAgIFBFTkRJTkcgPSAnUEVORElORycsXG4gICAgUkVKRUNURUQgPSAnUkVKRUNURUQnLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VFbnRpdHkge1xuICAgIGV4cGlyYXRpb25fbW9udGg/OiBudW1iZXI7XG4gICAgZXhwaXJhdGlvbl95ZWFyPzogbnVtYmVyO1xuICAgIGV4cGlyZWQ6IGJvb2xlYW47XG4gICAgaWQ/OiBudW1iZXI7XG4gICAgaXNfZGVmYXVsdD86IGJvb2xlYW47XG4gICAgaXNfZnVsbHlfZGVmaW5lZDogYm9vbGVhbjtcbiAgICBtYXNrZWRfbnVtYmVyOiBzdHJpbmc7XG4gICAgcGF5bWVudHM6IHtcbiAgICAgICAgYW1vdW50OiBzdHJpbmc7XG4gICAgICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgICAgIGRpc3BsYXlfYW1vdW50OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3Q6IHtcbiAgICAgICAgICAgIGN1cnJlbmN5PzogQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICAgICAgZGlzcGxheV9wcmljZTogc3RyaW5nO1xuICAgICAgICAgICAgbmFtZTogc3RyaW5nO1xuICAgICAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgICAgICBwcm9kdWN0X3R5cGU6IEJ1bGtSZWFkUGF5bWVudGNhcmRzUmVzcG9uc2VQcm9kdWN0VHlwZTtcbiAgICAgICAgfTtcbiAgICAgICAgc3RhdHVzPzogQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZVN0YXR1cztcbiAgICAgICAgc3RhdHVzX2xlZGdlcj86IE9iamVjdDtcbiAgICB9W107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZSB7XG4gICAgZGF0YTogQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL3BheW1lbnRfY2FyZC5weS8jbGluZXMtNTJcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENyZWF0ZVBheW1lbnRjYXJkQm9keSB7XG4gICAgZXhwaXJhdGlvbl9tb250aDogbnVtYmVyO1xuICAgIGV4cGlyYXRpb25feWVhcjogbnVtYmVyO1xuICAgIG1hcmtfYXNfZGVmYXVsdD86IGJvb2xlYW47XG4gICAgbWFza2VkX251bWJlcjogc3RyaW5nO1xuICAgIHRva2VuOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvcGF5bWVudF9jYXJkLnB5LyNsaW5lcy05XG4gKi9cblxuZXhwb3J0IGVudW0gQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gQ3JlYXRlUGF5bWVudGNhcmRSZXNwb25zZVByb2R1Y3RUeXBlIHtcbiAgICBET05BVElPTiA9ICdET05BVElPTicsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBlbnVtIENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VTdGF0dXMge1xuICAgIENBTkNFTEVEID0gJ0NBTkNFTEVEJyxcbiAgICBDT01QTEVURUQgPSAnQ09NUExFVEVEJyxcbiAgICBORVcgPSAnTkVXJyxcbiAgICBQRU5ESU5HID0gJ1BFTkRJTkcnLFxuICAgIFJFSkVDVEVEID0gJ1JFSkVDVEVEJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlIHtcbiAgICBleHBpcmF0aW9uX21vbnRoPzogbnVtYmVyO1xuICAgIGV4cGlyYXRpb25feWVhcj86IG51bWJlcjtcbiAgICBleHBpcmVkOiBib29sZWFuO1xuICAgIGlkPzogbnVtYmVyO1xuICAgIGlzX2RlZmF1bHQ/OiBib29sZWFuO1xuICAgIGlzX2Z1bGx5X2RlZmluZWQ6IGJvb2xlYW47XG4gICAgbWFza2VkX251bWJlcjogc3RyaW5nO1xuICAgIHBheW1lbnRzOiB7XG4gICAgICAgIGFtb3VudDogc3RyaW5nO1xuICAgICAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgICAgICBkaXNwbGF5X2Ftb3VudDogc3RyaW5nO1xuICAgICAgICBwcm9kdWN0OiB7XG4gICAgICAgICAgICBjdXJyZW5jeT86IENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VDdXJyZW5jeTtcbiAgICAgICAgICAgIGRpc3BsYXlfcHJpY2U6IHN0cmluZztcbiAgICAgICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgICAgIHByaWNlPzogc3RyaW5nO1xuICAgICAgICAgICAgcHJvZHVjdF90eXBlOiBDcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgICAgIH07XG4gICAgICAgIHN0YXR1cz86IENyZWF0ZVBheW1lbnRjYXJkUmVzcG9uc2VTdGF0dXM7XG4gICAgICAgIHN0YXR1c19sZWRnZXI/OiBPYmplY3Q7XG4gICAgfVtdO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjLy52ZW52L3NyYy9saWx5L2xpbHkvYmFzZS9zZXJpYWxpemVycy5weS8jbGluZXMtMTU4XG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBEZWxldGVQYXltZW50Y2FyZFJlc3BvbnNlIHt9XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvdmlld3MvcGF5bWVudF9jYXJkLnB5LyNsaW5lcy0yMDRcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRCb2R5IHtcbiAgICBwYXltZW50X3Rva2VuOiBzdHJpbmc7XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1hdXRoLXNlcnZpY2Uvc3JjLzA5ZDc0ZTFjMWY2ODcxNzM5MjY4Y2Q3NDMxNWI0ZjExNDU5MmFmMmMvY29zcGhlcmVfYXV0aF9zZXJ2aWNlL3BheW1lbnQvc2VyaWFsaXplcnMvcGF5bWVudC5weS8jbGluZXMtOVxuICovXG5cbmV4cG9ydCBlbnVtIFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZUN1cnJlbmN5IHtcbiAgICBQTE4gPSAnUExOJyxcbn1cblxuZXhwb3J0IGVudW0gUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlUHJvZHVjdFR5cGUge1xuICAgIERPTkFUSU9OID0gJ0RPTkFUSU9OJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZID0gJ1NVQlNDUklQVElPTl9MRUFSTkVSX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9MRUFSTkVSX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFknLFxuICAgIFNVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZID0gJ1NVQlNDUklQVElPTl9NRU5UT1JfWUVBUkxZJyxcbn1cblxuZXhwb3J0IGVudW0gUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlU3RhdHVzIHtcbiAgICBDQU5DRUxFRCA9ICdDQU5DRUxFRCcsXG4gICAgQ09NUExFVEVEID0gJ0NPTVBMRVRFRCcsXG4gICAgTkVXID0gJ05FVycsXG4gICAgUEVORElORyA9ICdQRU5ESU5HJyxcbiAgICBSRUpFQ1RFRCA9ICdSRUpFQ1RFRCcsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlIHtcbiAgICBhbW91bnQ6IHN0cmluZztcbiAgICBjcmVhdGVkX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgIGRpc3BsYXlfYW1vdW50OiBzdHJpbmc7XG4gICAgcHJvZHVjdDoge1xuICAgICAgICBjdXJyZW5jeT86IFBheVdpdGhEZWZhdWx0UGF5bWVudENhcmRSZXNwb25zZUN1cnJlbmN5O1xuICAgICAgICBkaXNwbGF5X3ByaWNlOiBzdHJpbmc7XG4gICAgICAgIG5hbWU6IHN0cmluZztcbiAgICAgICAgcHJpY2U/OiBzdHJpbmc7XG4gICAgICAgIHByb2R1Y3RfdHlwZTogUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlUHJvZHVjdFR5cGU7XG4gICAgfTtcbiAgICBzdGF0dXM/OiBQYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkUmVzcG9uc2VTdGF0dXM7XG4gICAgc3RhdHVzX2xlZGdlcj86IE9iamVjdDtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC9tb2RlbHMvcGF5dS5weS8jbGluZXMtMzEzXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBSZW5kZXJQYXltZW50Q2FyZFdpZGdldFJlc3BvbnNlIHtcbiAgICBjdXJyZW5jeV9jb2RlOiBzdHJpbmc7XG4gICAgY3VzdG9tZXJfZW1haWw/OiBzdHJpbmc7XG4gICAgY3VzdG9tZXJfbGFuZ3VhZ2U6IHN0cmluZztcbiAgICBtZXJjaGFudF9wb3NfaWQ6IHN0cmluZztcbiAgICByZWN1cnJpbmdfcGF5bWVudDogYm9vbGVhbjtcbiAgICBzaG9wX25hbWU6IHN0cmluZztcbiAgICBzaWc6IHN0cmluZztcbiAgICBzdG9yZV9jYXJkOiBib29sZWFuO1xuICAgIHRvdGFsX2Ftb3VudDogc3RyaW5nO1xuICAgIHdpZGdldF9tb2RlPzogc3RyaW5nO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUGF5bWVudHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcGF5bWVudHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFBheW1lbnRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIFVwZGF0ZSB0aGUgc3RhdHVzIG9mIGEgZ2l2ZW4gUGF5bWVudFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFVwZGF0ZSB0aGUgUGF5bWVudCBpbnN0YW5jZSBpZGVudGlmaWVkIGJ5IHRoZSBgc2Vzc2lvbl9pZGAuIFRoaXMgY29tbWFuZCBpcyBmb3IgZXh0ZXJuYWwgdXNlIG9ubHkgdGhlcmVmb3JlIGl0IGRvZXNuJ3QgZXhwb3NlIGludGVybmFsIGlkcyBvZiB0aGUgcGF5bWVudHMgYnV0IHJhdGhlciBzZXNzaW9uIGlkLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVQYXltZW50U3RhdHVzKGJvZHk6IFguVXBkYXRlUGF5bWVudFN0YXR1c0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlUGF5bWVudFN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5VcGRhdGVQYXltZW50U3RhdHVzUmVzcG9uc2U+KCcvcGF5bWVudHMvKD9QPHNlc3Npb25faWQ+W1xcd1xcLV0rKScsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogUmVjYWxsIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3JlY2FsbC5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUmVjYWxsRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBSZWNhbGwgU2Vzc2lvblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbmRlciBSZWNhbGwgU2Vzc2lvbiBjb21wb3NlZCBvdXQgb2YgdGhlIHNlcXVlbmNlIG9mIENhcmRzIHRoYXQgc2hvdWxkIGJlIHJlY2FsbGVkIGluIGEgZ2l2ZW4gb3JkZXIuIEJhc2VkIG9uIHRoZSBSZWNhbGxBdHRlbXB0IHN0YXRzIHJlY29tbWVuZCBhbm90aGVyIENhcmQgdG8gcmVjYWxsIGluIG9yZGVyIHRvIG1heGltaXplIHRoZSByZWNhbGwgc3BlZWQgYW5kIHN1Y2Nlc3MgcmF0ZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlUmVjYWxsU2Vzc2lvbihib2R5OiBYLkNyZWF0ZVJlY2FsbFNlc3Npb25Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVJlY2FsbFNlc3Npb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlUmVjYWxsU2Vzc2lvblJlc3BvbnNlPignL3JlY2FsbC9zZXNzaW9ucy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgUmVjYWxsIFN1bW1hcnlcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIHN1bW1hcnkgc3RhdHMgZm9yIGNhcmRzIGFuZCB0aGVpciByZWNhbGxfc2NvcmUgZm9yIGEgZ2l2ZW4gVXNlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZFJlY2FsbFN1bW1hcnkoKTogRGF0YVN0YXRlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4oJy9yZWNhbGwvc3VtbWFyeS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRSZWNhbGxTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4oJy9yZWNhbGwvc3VtbWFyeS8nLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbn0iLCIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFN1YnNjcmlwdGlvbiBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9zdWJzY3JpcHRpb25zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBTdWJzY3JpcHRpb25zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIFJlcXVlc3QgYSBzdWJzY3JpcHRpb24gY2hhbmdlXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogV2hlbmV2ZXIgdGhlIHVzZXIgd2FudHMgdG8gY2hhbmdlIGhlciBzdWJzY3JpcHRpb24gaXQgbXVzdCBoYXBwZW4gdGhyb3VnaCB0aGlzIGVuZHBvaW50LiBJdCdzIHN0aWxsIHBvc3NpYmxlIHRoYXQgdGhlIHN1YnNjcmlwdGlvbiB3aWxsIGNoYW5nZSB3aXRob3V0IHVzZXIgYXNraW5nIGZvciBpdCwgYnV0IHRoYXQgY2FuIGhhcHBlbiB3aGVuIGRvd25ncmFkaW5nIGR1ZSB0byBtaXNzaW5nIHBheW1lbnQuXG4gICAgICovXG4gICAgcHVibGljIGNoYW5nZVN1YnNjcmlwdGlvbihib2R5OiBYLkNoYW5nZVN1YnNjcmlwdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvc3Vic2NyaXB0aW9uLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59IiwiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBTdWJzY3JpcHRpb24gTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWF1dGgtc2VydmljZS9zcmMvMDlkNzRlMWMxZjY4NzE3MzkyNjhjZDc0MzE1YjRmMTE0NTkyYWYyYy9jb3NwaGVyZV9hdXRoX3NlcnZpY2UvcGF5bWVudC92aWV3cy9zdWJzY3JpcHRpb24ucHkvI2xpbmVzLTI4XG4gKi9cblxuZXhwb3J0IGVudW0gQ2hhbmdlU3Vic2NyaXB0aW9uQm9keVN1YnNjcmlwdGlvblR5cGUge1xuICAgIEZSRUUgPSAnRlJFRScsXG4gICAgU1VCU0NSSVBUSU9OX0xFQVJORVJfTU9OVEhMWSA9ICdTVUJTQ1JJUFRJT05fTEVBUk5FUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTEVBUk5FUl9ZRUFSTFkgPSAnU1VCU0NSSVBUSU9OX0xFQVJORVJfWUVBUkxZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX01PTlRITFkgPSAnU1VCU0NSSVBUSU9OX01FTlRPUl9NT05USExZJyxcbiAgICBTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWSA9ICdTVUJTQ1JJUFRJT05fTUVOVE9SX1lFQVJMWScsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2hhbmdlU3Vic2NyaXB0aW9uQm9keSB7XG4gICAgc3Vic2NyaXB0aW9uX3R5cGU6IENoYW5nZVN1YnNjcmlwdGlvbkJvZHlTdWJzY3JpcHRpb25UeXBlO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtYXV0aC1zZXJ2aWNlL3NyYy8wOWQ3NGUxYzFmNjg3MTczOTI2OGNkNzQzMTViNGYxMTQ1OTJhZjJjL2Nvc3BoZXJlX2F1dGhfc2VydmljZS9wYXltZW50L3ZpZXdzL3N1YnNjcmlwdGlvbi5weS8jbGluZXMtMzlcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIENoYW5nZVN1YnNjcmlwdGlvblJlc3BvbnNlIHtcbiAgICBhdF9fcHJvY2VzczogT2JqZWN0O1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogVGFza3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vdGFza3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFRhc2tzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgVGFza3NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IHRhc2tzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkVGFza3MocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4oJy90YXNrcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFRhc2sgQmluc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgVGFza3MgQmluc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFRhc2tCaW5zKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvYmlucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrQmluczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza0JpbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvYmlucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogVGFza3MgTWFuYWdlbWVudCBEb21haW4gTW9kZWxzXG4gKi9cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy9iOGRlYzNjZjEzZDE4OTcxMDkyMjA3ODdmOTk1NTQ2NTU4ZGU0NzdkL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL3Rhc2svdmlld3MucHkvI2xpbmVzLTMzXG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRUYXNrc1F1ZXJ5UXVldWVUeXBlIHtcbiAgICBETiA9ICdETicsXG4gICAgSFAgPSAnSFAnLFxuICAgIE9UID0gJ09UJyxcbiAgICBQUiA9ICdQUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrc1F1ZXJ5IHtcbiAgICBhc2NlbmRpbmc/OiBib29sZWFuO1xuICAgIGxpbWl0PzogbnVtYmVyO1xuICAgIG9mZnNldD86IG51bWJlcjtcbiAgICBxdWV1ZV90eXBlPzogQnVsa1JlYWRUYXNrc1F1ZXJ5UXVldWVUeXBlO1xufVxuXG4vKipcbiAqIGh0dHBzOi8vYml0YnVja2V0Lm9yZy9nb29kYWkvY29zcGhlcmUtZW50aXR5LXNlcnZpY2Uvc3JjL2I4ZGVjM2NmMTNkMTg5NzEwOTIyMDc4N2Y5OTU1NDY1NThkZTQ3N2QvY29zcGhlcmVfZW50aXR5X3NlcnZpY2UvdGFzay9zZXJpYWxpemVycy5weS8jbGluZXMtNTVcbiAqL1xuXG5leHBvcnQgZW51bSBCdWxrUmVhZFRhc2tzUmVzcG9uc2VRdWV1ZVR5cGUge1xuICAgIEROID0gJ0ROJyxcbiAgICBIUCA9ICdIUCcsXG4gICAgT1QgPSAnT1QnLFxuICAgIFBSID0gJ1BSJyxcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHkge1xuICAgIGFyY2hpdmVkPzogYm9vbGVhbjtcbiAgICBjb250ZW50PzogT2JqZWN0O1xuICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgZG9uZV9kYXRlOiBzdHJpbmc7XG4gICAgZG9uZV90aW1lc3RhbXA6IG51bWJlcjtcbiAgICBpZD86IG51bWJlcjtcbiAgICBvcmRlcl9udW1iZXI/OiBudW1iZXI7XG4gICAgcXVldWVfdHlwZT86IEJ1bGtSZWFkVGFza3NSZXNwb25zZVF1ZXVlVHlwZTtcbiAgICB0b3RhbF90aW1lPzogbnVtYmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza3NSZXNwb25zZSB7XG4gICAgZGF0YTogQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W107XG59XG5cbi8qKlxuICogaHR0cHM6Ly9iaXRidWNrZXQub3JnL2dvb2RhaS9jb3NwaGVyZS1lbnRpdHktc2VydmljZS9zcmMvYjhkZWMzY2YxM2QxODk3MTA5MjIwNzg3Zjk5NTU0NjU1OGRlNDc3ZC9jb3NwaGVyZV9lbnRpdHlfc2VydmljZS90YXNrL3ZpZXdzLnB5LyNsaW5lcy0zM1xuICovXG5cbmV4cG9ydCBlbnVtIEJ1bGtSZWFkVGFza0JpbnNRdWVyeVF1ZXVlVHlwZSB7XG4gICAgRE4gPSAnRE4nLFxuICAgIEhQID0gJ0hQJyxcbiAgICBPVCA9ICdPVCcsXG4gICAgUFIgPSAnUFInLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEJ1bGtSZWFkVGFza0JpbnNRdWVyeSB7XG4gICAgYXNjZW5kaW5nPzogYm9vbGVhbjtcbiAgICBsaW1pdD86IG51bWJlcjtcbiAgICBvZmZzZXQ/OiBudW1iZXI7XG4gICAgcXVldWVfdHlwZT86IEJ1bGtSZWFkVGFza0JpbnNRdWVyeVF1ZXVlVHlwZTtcbn1cblxuLyoqXG4gKiBodHRwczovL2JpdGJ1Y2tldC5vcmcvZ29vZGFpL2Nvc3BoZXJlLWVudGl0eS1zZXJ2aWNlL3NyYy9iOGRlYzNjZjEzZDE4OTcxMDkyMjA3ODdmOTk1NTQ2NTU4ZGU0NzdkL2Nvc3BoZXJlX2VudGl0eV9zZXJ2aWNlL3Rhc2svc2VyaWFsaXplcnMucHkvI2xpbmVzLTcxXG4gKi9cblxuZXhwb3J0IGVudW0gQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlUXVldWVUeXBlIHtcbiAgICBETiA9ICdETicsXG4gICAgSFAgPSAnSFAnLFxuICAgIE9UID0gJ09UJyxcbiAgICBQUiA9ICdQUicsXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5IHtcbiAgICBkb25lX2RhdGU6IHN0cmluZztcbiAgICB0YXNrczoge1xuICAgICAgICBhcmNoaXZlZD86IGJvb2xlYW47XG4gICAgICAgIGNvbnRlbnQ/OiBPYmplY3Q7XG4gICAgICAgIGNyZWF0ZWRfdGltZXN0YW1wOiBudW1iZXI7XG4gICAgICAgIGRvbmVfZGF0ZTogc3RyaW5nO1xuICAgICAgICBkb25lX3RpbWVzdGFtcDogbnVtYmVyO1xuICAgICAgICBpZD86IG51bWJlcjtcbiAgICAgICAgb3JkZXJfbnVtYmVyPzogbnVtYmVyO1xuICAgICAgICBxdWV1ZV90eXBlPzogQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlUXVldWVUeXBlO1xuICAgICAgICB0b3RhbF90aW1lPzogbnVtYmVyO1xuICAgIH1bXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBCdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2Uge1xuICAgIGRhdGE6IEJ1bGtSZWFkVGFza0JpbnNSZXNwb25zZUVudGl0eVtdO1xufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogV29yZHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vd29yZHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFdvcmRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgV29yZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFdvcmRzIGJ5IGZpcnN0IGNoYXJhY3Rlci4gSXQgYWxsb3dzIG9uZSB0byBmZXRjaCBsaXN0IG9mIHdvcmRzIGJ5IGZpcnN0IGNoYXJhY3Rlci5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRXb3Jkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPignL3dvcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRXb3Jkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogRmFjYWRlIEFQSSBTZXJ2aWNlIGZvciBhbGwgZG9tYWluc1xuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlLCBJbmplY3RvciB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuXG5pbXBvcnQgeyBEYXRhU3RhdGUsIE9wdGlvbnMgfSBmcm9tICcuL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4uL2RvbWFpbnMvaW5kZXgnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQVBJU2VydmljZSB7XG5cbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGluamVjdG9yOiBJbmplY3Rvcikge31cblxuICAgIC8qKlxuICAgICAqIEFjY291bnQgU2V0dGluZ3MgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9hY2NvdW50X3NldHRpbmdzRG9tYWluOiBYLkFjY291bnRTZXR0aW5nc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGFjY291bnRfc2V0dGluZ3NEb21haW4oKTogWC5BY2NvdW50U2V0dGluZ3NEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2FjY291bnRfc2V0dGluZ3NEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2FjY291bnRfc2V0dGluZ3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkFjY291bnRTZXR0aW5nc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2FjY291bnRfc2V0dGluZ3NEb21haW47XG4gICAgfVxuXG4gICAgcmVhZEFjY291bnRzZXR0aW5nKCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRfc2V0dGluZ3NEb21haW4ucmVhZEFjY291bnRzZXR0aW5nKCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRBY2NvdW50c2V0dGluZzIoKTogT2JzZXJ2YWJsZTxYLlJlYWRBY2NvdW50c2V0dGluZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRfc2V0dGluZ3NEb21haW4ucmVhZEFjY291bnRzZXR0aW5nMigpO1xuICAgIH1cblxuICAgIHVwZGF0ZUFjY291bnRzZXR0aW5nKGJvZHk6IFguVXBkYXRlQWNjb3VudHNldHRpbmdCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUFjY291bnRzZXR0aW5nUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudF9zZXR0aW5nc0RvbWFpbi51cGRhdGVBY2NvdW50c2V0dGluZyhib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBY2NvdW50cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2FjY291bnRzRG9tYWluOiBYLkFjY291bnRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYWNjb3VudHNEb21haW4oKTogWC5BY2NvdW50c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fYWNjb3VudHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2FjY291bnRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5BY2NvdW50c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2FjY291bnRzRG9tYWluO1xuICAgIH1cblxuICAgIGFjdGl2YXRlQWNjb3VudChib2R5OiBYLkFjdGl2YXRlQWNjb3VudEJvZHkpOiBPYnNlcnZhYmxlPFguQWN0aXZhdGVBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uYWN0aXZhdGVBY2NvdW50KGJvZHkpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkQWNjb3VudHMocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQWNjb3VudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLmJ1bGtSZWFkQWNjb3VudHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRBY2NvdW50czIocGFyYW1zOiBYLkJ1bGtSZWFkQWNjb3VudHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEFjY291bnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5idWxrUmVhZEFjY291bnRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNoYW5nZVBhc3N3b3JkKGJvZHk6IFguQ2hhbmdlUGFzc3dvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNoYW5nZVBhc3N3b3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uY2hhbmdlUGFzc3dvcmQoYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlQWNjb3VudChib2R5OiBYLkNyZWF0ZUFjY291bnRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFjY291bnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hY2NvdW50c0RvbWFpbi5jcmVhdGVBY2NvdW50KGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRBY2NvdW50KCk6IERhdGFTdGF0ZTxYLlJlYWRBY2NvdW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4ucmVhZEFjY291bnQoKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEFjY291bnQyKCk6IE9ic2VydmFibGU8WC5SZWFkQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnJlYWRBY2NvdW50MigpO1xuICAgIH1cblxuICAgIHJlc2V0UGFzc3dvcmQoYm9keTogWC5SZXNldFBhc3N3b3JkQm9keSk6IE9ic2VydmFibGU8WC5SZXNldFBhc3N3b3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4ucmVzZXRQYXNzd29yZChib2R5KTtcbiAgICB9XG5cbiAgICBzZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbChib2R5OiBYLlNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsQm9keSk6IE9ic2VydmFibGU8WC5TZW5kQWNjb3VudEFjdGl2YXRpb25FbWFpbFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnNlbmRBY2NvdW50QWN0aXZhdGlvbkVtYWlsKGJvZHkpO1xuICAgIH1cblxuICAgIHNlbmRSZXNldFBhc3N3b3JkRW1haWwoYm9keTogWC5TZW5kUmVzZXRQYXNzd29yZEVtYWlsQm9keSk6IE9ic2VydmFibGU8WC5TZW5kUmVzZXRQYXNzd29yZEVtYWlsUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYWNjb3VudHNEb21haW4uc2VuZFJlc2V0UGFzc3dvcmRFbWFpbChib2R5KTtcbiAgICB9XG5cbiAgICB1cGRhdGVBY2NvdW50KGJvZHk6IFguVXBkYXRlQWNjb3VudEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQWNjb3VudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmFjY291bnRzRG9tYWluLnVwZGF0ZUFjY291bnQoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQXR0ZW1wdCBTdGF0cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2F0dGVtcHRfc3RhdHNEb21haW46IFguQXR0ZW1wdFN0YXRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYXR0ZW1wdF9zdGF0c0RvbWFpbigpOiBYLkF0dGVtcHRTdGF0c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fYXR0ZW1wdF9zdGF0c0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fYXR0ZW1wdF9zdGF0c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQXR0ZW1wdFN0YXRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fYXR0ZW1wdF9zdGF0c0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEF0dGVtcHRzdGF0cyhwYXJhbXM6IFguQnVsa1JlYWRBdHRlbXB0c3RhdHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdF9zdGF0c0RvbWFpbi5idWxrUmVhZEF0dGVtcHRzdGF0cyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEF0dGVtcHRzdGF0czIocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0X3N0YXRzRG9tYWluLmJ1bGtSZWFkQXR0ZW1wdHN0YXRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGNyZWF0ZUF0dGVtcHRzdGF0KGJvZHk6IFguQ3JlYXRlQXR0ZW1wdHN0YXRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUF0dGVtcHRzdGF0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdF9zdGF0c0RvbWFpbi5jcmVhdGVBdHRlbXB0c3RhdChib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0KGJvZHk6IFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRfc3RhdHNEb21haW4uY3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdChib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBdHRlbXB0cyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2F0dGVtcHRzRG9tYWluOiBYLkF0dGVtcHRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgYXR0ZW1wdHNEb21haW4oKTogWC5BdHRlbXB0c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fYXR0ZW1wdHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2F0dGVtcHRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5BdHRlbXB0c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2F0dGVtcHRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRzRG9tYWluLmJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzKGNhcmRJZCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkQXR0ZW1wdHNCeUNhcmRzMihjYXJkSWQ6IGFueSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEF0dGVtcHRzQnlDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXR0ZW1wdHNEb21haW4uYnVsa1JlYWRBdHRlbXB0c0J5Q2FyZHMyKGNhcmRJZCk7XG4gICAgfVxuXG4gICAgY3JlYXRlQXR0ZW1wdChib2R5OiBYLkNyZWF0ZUF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdHRlbXB0c0RvbWFpbi5jcmVhdGVBdHRlbXB0KGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZUF0dGVtcHQoYXR0ZW1wdElkOiBhbnksIGJvZHk6IFguVXBkYXRlQXR0ZW1wdEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQXR0ZW1wdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF0dGVtcHRzRG9tYWluLnVwZGF0ZUF0dGVtcHQoYXR0ZW1wdElkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBBdXRoIFRva2VucyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2F1dGhfdG9rZW5zRG9tYWluOiBYLkF1dGhUb2tlbnNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBhdXRoX3Rva2Vuc0RvbWFpbigpOiBYLkF1dGhUb2tlbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2F1dGhfdG9rZW5zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9hdXRoX3Rva2Vuc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguQXV0aFRva2Vuc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2F1dGhfdG9rZW5zRG9tYWluO1xuICAgIH1cblxuICAgIGF1dGhvcml6ZUF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguQXV0aG9yaXplQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uYXV0aG9yaXplQXV0aFRva2VuKCk7XG4gICAgfVxuXG4gICAgY3JlYXRlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi5jcmVhdGVBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi5jcmVhdGVGYWNlYm9va0Jhc2VkQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlRmFjZWJvb2tCYXNlZE1vYmlsZUF1dGhUb2tlbihib2R5KTtcbiAgICB9XG5cbiAgICBjcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmF1dGhfdG9rZW5zRG9tYWluLmNyZWF0ZUdvb2dsZUJhc2VkQXV0aFRva2VuKGJvZHkpO1xuICAgIH1cblxuICAgIGNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlR29vZ2xlQmFzZWRNb2JpbGVBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuYXV0aF90b2tlbnNEb21haW4uY3JlYXRlR29vZ2xlQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keSk7XG4gICAgfVxuXG4gICAgdXBkYXRlQXV0aFRva2VuKCk6IE9ic2VydmFibGU8WC5VcGRhdGVBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5hdXRoX3Rva2Vuc0RvbWFpbi51cGRhdGVBdXRoVG9rZW4oKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXJkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2NhcmRzRG9tYWluOiBYLkNhcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgY2FyZHNEb21haW4oKTogWC5DYXJkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fY2FyZHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2NhcmRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5DYXJkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2NhcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtEZWxldGVDYXJkcyhwYXJhbXM6IFguQnVsa0RlbGV0ZUNhcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4uYnVsa0RlbGV0ZUNhcmRzKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRDYXJkcyhwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2FyZHNEb21haW4uYnVsa1JlYWRDYXJkcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZENhcmRzMihwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLmJ1bGtSZWFkQ2FyZHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlQ2FyZChib2R5OiBYLkNyZWF0ZUNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5jcmVhdGVDYXJkKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRDYXJkKGNhcmRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZENhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5yZWFkQ2FyZChjYXJkSWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkQ2FyZDIoY2FyZElkOiBhbnksIHBhcmFtcz86IGFueSk6IE9ic2VydmFibGU8WC5SZWFkQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLnJlYWRDYXJkMihjYXJkSWQsIHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRHZW9tZXRyaWVzT25seTIocGFyYW1zOiBhbnkpOiBPYnNlcnZhYmxlPGFueT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jYXJkc0RvbWFpbi5idWxrUmVhZEdlb21ldHJpZXNPbmx5MihwYXJhbXMpO1xuICAgIH1cblxuICAgIHVwZGF0ZUNhcmQoY2FyZElkOiBhbnksIGJvZHk6IFguVXBkYXRlQ2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhcmRzRG9tYWluLnVwZGF0ZUNhcmQoY2FyZElkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDYXRlZ29yaWVzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfY2F0ZWdvcmllc0RvbWFpbjogWC5DYXRlZ29yaWVzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgY2F0ZWdvcmllc0RvbWFpbigpOiBYLkNhdGVnb3JpZXNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2NhdGVnb3JpZXNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2NhdGVnb3JpZXNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkNhdGVnb3JpZXNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9jYXRlZ29yaWVzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkQ2F0ZWdvcmllcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZENhdGVnb3JpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNhdGVnb3JpZXNEb21haW4uYnVsa1JlYWRDYXRlZ29yaWVzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkQ2F0ZWdvcmllczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQ2F0ZWdvcmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2F0ZWdvcmllc0RvbWFpbi5idWxrUmVhZENhdGVnb3JpZXMyKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ29udGFjdCBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2NvbnRhY3RzRG9tYWluOiBYLkNvbnRhY3RzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgY29udGFjdHNEb21haW4oKTogWC5Db250YWN0c0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fY29udGFjdHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2NvbnRhY3RzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Db250YWN0c0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2NvbnRhY3RzRG9tYWluO1xuICAgIH1cblxuICAgIGNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHk6IFguQ3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUFub255bW91c0NvbnRhY3RBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29udGFjdHNEb21haW4uY3JlYXRlQW5vbnltb3VzQ29udGFjdEF0dGVtcHQoYm9keSk7XG4gICAgfVxuXG4gICAgc2VuZEF1dGhlbnRpY2F0ZWRDb250YWN0TWVzc2FnZShib2R5OiBYLlNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2VCb2R5KTogT2JzZXJ2YWJsZTxYLlNlbmRBdXRoZW50aWNhdGVkQ29udGFjdE1lc3NhZ2VSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jb250YWN0c0RvbWFpbi5zZW5kQXV0aGVudGljYXRlZENvbnRhY3RNZXNzYWdlKGJvZHkpO1xuICAgIH1cblxuICAgIHZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0KGJvZHk6IFguVmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLlZlcmlmeUFub255bW91c0NvbnRhY3RBdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29udGFjdHNEb21haW4udmVyaWZ5QW5vbnltb3VzQ29udGFjdEF0dGVtcHQoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRG9uYXRpb25zIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZG9uYXRpb25zRG9tYWluOiBYLkRvbmF0aW9uc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGRvbmF0aW9uc0RvbWFpbigpOiBYLkRvbmF0aW9uc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZG9uYXRpb25zRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9kb25hdGlvbnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkRvbmF0aW9uc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2RvbmF0aW9uc0RvbWFpbjtcbiAgICB9XG5cbiAgICBjaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uKHBhcmFtczogWC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUXVlcnkpOiBEYXRhU3RhdGU8WC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb24ocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgY2hlY2tJZkNhbkF0dGVtcHREb25hdGlvbjIocGFyYW1zOiBYLkNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb25RdWVyeSk6IE9ic2VydmFibGU8WC5DaGVja0lmQ2FuQXR0ZW1wdERvbmF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZG9uYXRpb25zRG9tYWluLmNoZWNrSWZDYW5BdHRlbXB0RG9uYXRpb24yKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlQW5vbnltb3VzRG9uYXRpb24oYm9keTogWC5DcmVhdGVBbm9ueW1vdXNEb25hdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQW5vbnltb3VzRG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5kb25hdGlvbnNEb21haW4uY3JlYXRlQW5vbnltb3VzRG9uYXRpb24oYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlRG9uYXRpb24oYm9keTogWC5DcmVhdGVEb25hdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRG9uYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5kb25hdGlvbnNEb21haW4uY3JlYXRlRG9uYXRpb24oYm9keSk7XG4gICAgfVxuXG4gICAgY3JlYXRlRG9uYXRpb25hdHRlbXB0KGJvZHk6IFguQ3JlYXRlRG9uYXRpb25hdHRlbXB0Qm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEb25hdGlvbmF0dGVtcHRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5kb25hdGlvbnNEb21haW4uY3JlYXRlRG9uYXRpb25hdHRlbXB0KGJvZHkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEV4dGVybmFsIEFwcHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9leHRlcm5hbF9hcHBzRG9tYWluOiBYLkV4dGVybmFsQXBwc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGV4dGVybmFsX2FwcHNEb21haW4oKTogWC5FeHRlcm5hbEFwcHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2V4dGVybmFsX2FwcHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2V4dGVybmFsX2FwcHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkV4dGVybmFsQXBwc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2V4dGVybmFsX2FwcHNEb21haW47XG4gICAgfVxuXG4gICAgYXV0aG9yaXplRXh0ZXJuYWxBcHBBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLkF1dGhvcml6ZUV4dGVybmFsQXBwQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZXh0ZXJuYWxfYXBwc0RvbWFpbi5hdXRob3JpemVFeHRlcm5hbEFwcEF1dGhUb2tlbigpO1xuICAgIH1cblxuICAgIGNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlRXh0ZXJuYWxBcHBBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUV4dGVybmFsQXBwQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZXh0ZXJuYWxfYXBwc0RvbWFpbi5jcmVhdGVFeHRlcm5hbEFwcEF1dGhUb2tlbihib2R5KTtcbiAgICB9XG5cbiAgICByZWFkRXh0ZXJuYWxhcHBjb25mKHBhcmFtczogWC5SZWFkRXh0ZXJuYWxhcHBjb25mUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkRXh0ZXJuYWxhcHBjb25mUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZXh0ZXJuYWxfYXBwc0RvbWFpbi5yZWFkRXh0ZXJuYWxhcHBjb25mKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRFeHRlcm5hbGFwcGNvbmYyKHBhcmFtczogWC5SZWFkRXh0ZXJuYWxhcHBjb25mUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEV4dGVybmFsYXBwY29uZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmV4dGVybmFsX2FwcHNEb21haW4ucmVhZEV4dGVybmFsYXBwY29uZjIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBGb2N1cyBSZWNvcmRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZm9jdXNfcmVjb3Jkc0RvbWFpbjogWC5Gb2N1c1JlY29yZHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBmb2N1c19yZWNvcmRzRG9tYWluKCk6IFguRm9jdXNSZWNvcmRzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9mb2N1c19yZWNvcmRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9mb2N1c19yZWNvcmRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Gb2N1c1JlY29yZHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9mb2N1c19yZWNvcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGNyZWF0ZUZvY3VzcmVjb3JkKGJvZHk6IFguQ3JlYXRlRm9jdXNyZWNvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZvY3VzcmVjb3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZm9jdXNfcmVjb3Jkc0RvbWFpbi5jcmVhdGVGb2N1c3JlY29yZChib2R5KTtcbiAgICB9XG5cbiAgICByZWFkRm9jdXNSZWNvcmRTdW1tYXJ5KCk6IERhdGFTdGF0ZTxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mb2N1c19yZWNvcmRzRG9tYWluLnJlYWRGb2N1c1JlY29yZFN1bW1hcnkoKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEZvY3VzUmVjb3JkU3VtbWFyeTIoKTogT2JzZXJ2YWJsZTxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mb2N1c19yZWNvcmRzRG9tYWluLnJlYWRGb2N1c1JlY29yZFN1bW1hcnkyKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogRnJhZ21lbnQgSGFzaHRhZ3MgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9mcmFnbWVudF9oYXNodGFnc0RvbWFpbjogWC5GcmFnbWVudEhhc2h0YWdzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4oKTogWC5GcmFnbWVudEhhc2h0YWdzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9mcmFnbWVudF9oYXNodGFnc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkZyYWdtZW50SGFzaHRhZ3NEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9mcmFnbWVudF9oYXNodGFnc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZEZyYWdtZW50SGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF9oYXNodGFnc0RvbWFpbi5idWxrUmVhZEZyYWdtZW50SGFzaHRhZ3MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudF9oYXNodGFnc0RvbWFpbi5idWxrUmVhZEZyYWdtZW50SGFzaHRhZ3MyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50SGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnczIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudEhhc2h0YWdzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEZyYWdtZW50IFdvcmRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZnJhZ21lbnRfd29yZHNEb21haW46IFguRnJhZ21lbnRXb3Jkc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IGZyYWdtZW50X3dvcmRzRG9tYWluKCk6IFguRnJhZ21lbnRXb3Jkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fZnJhZ21lbnRfd29yZHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ZyYWdtZW50X3dvcmRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5GcmFnbWVudFdvcmRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZnJhZ21lbnRfd29yZHNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRGcmFnbWVudFdvcmRzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50V29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfd29yZHNEb21haW4uYnVsa1JlYWRGcmFnbWVudFdvcmRzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkRnJhZ21lbnRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRXb3Jkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRfd29yZHNEb21haW4uYnVsa1JlYWRGcmFnbWVudFdvcmRzMihwYXJhbXMpO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X3dvcmRzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkcyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50X3dvcmRzRG9tYWluLmJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBGcmFnbWVudHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9mcmFnbWVudHNEb21haW46IFguRnJhZ21lbnRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZnJhZ21lbnRzRG9tYWluKCk6IFguRnJhZ21lbnRzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9mcmFnbWVudHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ZyYWdtZW50c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguRnJhZ21lbnRzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fZnJhZ21lbnRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkRnJhZ21lbnRzKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5idWxrUmVhZEZyYWdtZW50cyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEZyYWdtZW50czIocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5idWxrUmVhZEZyYWdtZW50czIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50cyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4uYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlRnJhZ21lbnQoKTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmNyZWF0ZUZyYWdtZW50KCk7XG4gICAgfVxuXG4gICAgZGVsZXRlRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLmRlbGV0ZUZyYWdtZW50KGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIG1lcmdlRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLk1lcmdlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5mcmFnbWVudHNEb21haW4ubWVyZ2VGcmFnbWVudChmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICBwdWJsaXNoRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlB1Ymxpc2hGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5wdWJsaXNoRnJhZ21lbnQoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgcmVhZEZyYWdtZW50KGZyYWdtZW50SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnQoZnJhZ21lbnRJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRGcmFnbWVudDIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnQyKGZyYWdtZW50SWQpO1xuICAgIH1cblxuICAgIHJlYWRGcmFnbWVudERpZmYoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnREaWZmKGZyYWdtZW50SWQpO1xuICAgIH1cbiAgICBcbiAgICByZWFkRnJhZ21lbnREaWZmMihmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi5yZWFkRnJhZ21lbnREaWZmMihmcmFnbWVudElkKTtcbiAgICB9XG5cbiAgICByZWFkRnJhZ21lbnRTYW1wbGUoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnJlYWRGcmFnbWVudFNhbXBsZShmcmFnbWVudElkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEZyYWdtZW50U2FtcGxlMihmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZnJhZ21lbnRzRG9tYWluLnJlYWRGcmFnbWVudFNhbXBsZTIoZnJhZ21lbnRJZCk7XG4gICAgfVxuXG4gICAgdXBkYXRlRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUZyYWdtZW50Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmZyYWdtZW50c0RvbWFpbi51cGRhdGVGcmFnbWVudChmcmFnbWVudElkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBHZW9tZXRyaWVzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfZ2VvbWV0cmllc0RvbWFpbjogWC5HZW9tZXRyaWVzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgZ2VvbWV0cmllc0RvbWFpbigpOiBYLkdlb21ldHJpZXNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX2dlb21ldHJpZXNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2dlb21ldHJpZXNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkdlb21ldHJpZXNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9nZW9tZXRyaWVzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkR2VvbWV0cmllcyhwYXJhbXM6IFguQnVsa1JlYWRHZW9tZXRyaWVzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEdlb21ldHJpZXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4uYnVsa1JlYWRHZW9tZXRyaWVzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkR2VvbWV0cmllczIocGFyYW1zOiBYLkJ1bGtSZWFkR2VvbWV0cmllc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkR2VvbWV0cmllc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5idWxrUmVhZEdlb21ldHJpZXMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgYnVsa1VwZGF0ZUdlb21ldHJpZXMoYm9keTogWC5CdWxrVXBkYXRlR2VvbWV0cmllc0JvZHkpOiBPYnNlcnZhYmxlPFguQnVsa1VwZGF0ZUdlb21ldHJpZXNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5nZW9tZXRyaWVzRG9tYWluLmJ1bGtVcGRhdGVHZW9tZXRyaWVzKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRHZW9tZXRyeUJ5Q2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRHZW9tZXRyeUJ5Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4ucmVhZEdlb21ldHJ5QnlDYXJkKGNhcmRJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRHZW9tZXRyeUJ5Q2FyZDIoY2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguUmVhZEdlb21ldHJ5QnlDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2VvbWV0cmllc0RvbWFpbi5yZWFkR2VvbWV0cnlCeUNhcmQyKGNhcmRJZCk7XG4gICAgfVxuXG4gICAgcmVhZEdyYXBoKHBhcmFtczogWC5SZWFkR3JhcGhRdWVyeSk6IERhdGFTdGF0ZTxYLlJlYWRHcmFwaFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4ucmVhZEdyYXBoKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRHcmFwaDIocGFyYW1zOiBYLlJlYWRHcmFwaFF1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRHcmFwaFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmdlb21ldHJpZXNEb21haW4ucmVhZEdyYXBoMihwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEhhc2h0YWdzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfaGFzaHRhZ3NEb21haW46IFguSGFzaHRhZ3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBoYXNodGFnc0RvbWFpbigpOiBYLkhhc2h0YWdzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9oYXNodGFnc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5faGFzaHRhZ3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkhhc2h0YWdzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5faGFzaHRhZ3NEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRIYXNodGFncyhwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4uYnVsa1JlYWRIYXNodGFncyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZEhhc2h0YWdzMihwYXJhbXM6IFguQnVsa1JlYWRIYXNodGFnc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLmJ1bGtSZWFkSGFzaHRhZ3MyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgY3JlYXRlSGFzaHRhZyhib2R5OiBYLkNyZWF0ZUhhc2h0YWdCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5jcmVhdGVIYXNodGFnKGJvZHkpO1xuICAgIH1cblxuICAgIGRlbGV0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIHBhcmFtczogWC5EZWxldGVIYXNodGFnUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLmRlbGV0ZUhhc2h0YWcoaGFzaHRhZ0lkLCBwYXJhbXMpO1xuICAgIH1cblxuICAgIHJlYWRIYXNodGFnc1RvYyhwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5oYXNodGFnc0RvbWFpbi5yZWFkSGFzaHRhZ3NUb2MocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZEhhc2h0YWdzVG9jMihwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzaHRhZ3NEb21haW4ucmVhZEhhc2h0YWdzVG9jMihwYXJhbXMpO1xuICAgIH1cblxuICAgIHVwZGF0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIGJvZHk6IFguVXBkYXRlSGFzaHRhZ0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc2h0YWdzRG9tYWluLnVwZGF0ZUhhc2h0YWcoaGFzaHRhZ0lkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBJbnRlcm5hbCBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX2ludGVybmFsRG9tYWluOiBYLkludGVybmFsRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgaW50ZXJuYWxEb21haW4oKTogWC5JbnRlcm5hbERvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5faW50ZXJuYWxEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX2ludGVybmFsRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5JbnRlcm5hbERvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX2ludGVybmFsRG9tYWluO1xuICAgIH1cblxuICAgIGRlbGV0ZUVudHJpZXNGb3JVc2VyKHVzZXJJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZUVudHJpZXNGb3JVc2VyUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaW50ZXJuYWxEb21haW4uZGVsZXRlRW50cmllc0ZvclVzZXIodXNlcklkKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBJbnZvaWNlIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfaW52b2ljZXNEb21haW46IFguSW52b2ljZXNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBpbnZvaWNlc0RvbWFpbigpOiBYLkludm9pY2VzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9pbnZvaWNlc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5faW52b2ljZXNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkludm9pY2VzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5faW52b2ljZXNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa1JlYWRJbnZvaWNlcygpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5idWxrUmVhZEludm9pY2VzKCk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkSW52b2ljZXMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZEludm9pY2VzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5idWxrUmVhZEludm9pY2VzMigpO1xuICAgIH1cblxuICAgIGNhbGN1bGF0ZURlYnQoKTogRGF0YVN0YXRlPFguQ2FsY3VsYXRlRGVidFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmludm9pY2VzRG9tYWluLmNhbGN1bGF0ZURlYnQoKTtcbiAgICB9XG4gICAgXG4gICAgY2FsY3VsYXRlRGVidDIoKTogT2JzZXJ2YWJsZTxYLkNhbGN1bGF0ZURlYnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5pbnZvaWNlc0RvbWFpbi5jYWxjdWxhdGVEZWJ0MigpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIExpbmtzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfbGlua3NEb21haW46IFguTGlua3NEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBsaW5rc0RvbWFpbigpOiBYLkxpbmtzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9saW5rc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fbGlua3NEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLkxpbmtzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fbGlua3NEb21haW47XG4gICAgfVxuXG4gICAgZGVsZXRlTGluayhmcm9tQ2FyZElkOiBhbnksIHRvQ2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlTGlua1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmxpbmtzRG9tYWluLmRlbGV0ZUxpbmsoZnJvbUNhcmRJZCwgdG9DYXJkSWQpO1xuICAgIH1cblxuICAgIHJlYWRPckNyZWF0ZUxpbmsoYm9keTogWC5SZWFkT3JDcmVhdGVMaW5rQm9keSk6IE9ic2VydmFibGU8WC5SZWFkT3JDcmVhdGVMaW5rUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubGlua3NEb21haW4ucmVhZE9yQ3JlYXRlTGluayhib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNZWRpYUl0ZW1zIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfbWVkaWFpdGVtc0RvbWFpbjogWC5NZWRpYWl0ZW1zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgbWVkaWFpdGVtc0RvbWFpbigpOiBYLk1lZGlhaXRlbXNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX21lZGlhaXRlbXNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX21lZGlhaXRlbXNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLk1lZGlhaXRlbXNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9tZWRpYWl0ZW1zRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkTWVkaWFpdGVtcyhwYXJhbXM6IFguQnVsa1JlYWRNZWRpYWl0ZW1zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZE1lZGlhaXRlbXNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4uYnVsa1JlYWRNZWRpYWl0ZW1zKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkTWVkaWFpdGVtczIocGFyYW1zOiBYLkJ1bGtSZWFkTWVkaWFpdGVtc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkTWVkaWFpdGVtc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5idWxrUmVhZE1lZGlhaXRlbXMyKHBhcmFtcyk7XG4gICAgfVxuXG4gICAgZGVsZXRlTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnksIHBhcmFtczogWC5EZWxldGVNZWRpYWl0ZW1RdWVyeSk6IE9ic2VydmFibGU8WC5EZWxldGVNZWRpYWl0ZW1SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLmRlbGV0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZCwgcGFyYW1zKTtcbiAgICB9XG5cbiAgICByZWFkTWVkaWFpdGVtKG1lZGlhaXRlbUlkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5yZWFkTWVkaWFpdGVtKG1lZGlhaXRlbUlkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZE1lZGlhaXRlbTIobWVkaWFpdGVtSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5yZWFkTWVkaWFpdGVtMihtZWRpYWl0ZW1JZCk7XG4gICAgfVxuXG4gICAgcmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkKHByb2Nlc3NJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi5yZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWQocHJvY2Vzc0lkKTtcbiAgICB9XG4gICAgXG4gICAgcmVhZE1lZGlhaXRlbUJ5UHJvY2Vzc0lkMihwcm9jZXNzSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkTWVkaWFpdGVtQnlQcm9jZXNzSWRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5tZWRpYWl0ZW1zRG9tYWluLnJlYWRNZWRpYWl0ZW1CeVByb2Nlc3NJZDIocHJvY2Vzc0lkKTtcbiAgICB9XG5cbiAgICByZWFkT3JDcmVhdGVNZWRpYWl0ZW0oYm9keTogWC5SZWFkT3JDcmVhdGVNZWRpYWl0ZW1Cb2R5KTogT2JzZXJ2YWJsZTxYLlJlYWRPckNyZWF0ZU1lZGlhaXRlbVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm1lZGlhaXRlbXNEb21haW4ucmVhZE9yQ3JlYXRlTWVkaWFpdGVtKGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZU1lZGlhaXRlbShtZWRpYWl0ZW1JZDogYW55LCBib2R5OiBYLlVwZGF0ZU1lZGlhaXRlbUJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlTWVkaWFpdGVtUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi51cGRhdGVNZWRpYWl0ZW0obWVkaWFpdGVtSWQsIGJvZHkpO1xuICAgIH1cblxuICAgIHVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uKG1lZGlhaXRlbUlkOiBhbnksIGJvZHk6IFguVXBkYXRlTWVkaWFpdGVtUmVwcmVzZW50YXRpb25Cb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZU1lZGlhaXRlbVJlcHJlc2VudGF0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMubWVkaWFpdGVtc0RvbWFpbi51cGRhdGVNZWRpYWl0ZW1SZXByZXNlbnRhdGlvbihtZWRpYWl0ZW1JZCwgYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTm90aWZpY2F0aW9uIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfbm90aWZpY2F0aW9uc0RvbWFpbjogWC5Ob3RpZmljYXRpb25zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgbm90aWZpY2F0aW9uc0RvbWFpbigpOiBYLk5vdGlmaWNhdGlvbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX25vdGlmaWNhdGlvbnNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX25vdGlmaWNhdGlvbnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLk5vdGlmaWNhdGlvbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9ub3RpZmljYXRpb25zRG9tYWluO1xuICAgIH1cblxuICAgIGFja25vd2xlZGdlTm90aWZpY2F0aW9uKG5vdGlmaWNhdGlvbklkOiBhbnkpOiBPYnNlcnZhYmxlPFguQWNrbm93bGVkZ2VOb3RpZmljYXRpb25SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5ub3RpZmljYXRpb25zRG9tYWluLmFja25vd2xlZGdlTm90aWZpY2F0aW9uKG5vdGlmaWNhdGlvbklkKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZE5vdGlmaWNhdGlvbnMocGFyYW1zOiBYLkJ1bGtSZWFkTm90aWZpY2F0aW9uc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWROb3RpZmljYXRpb25zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5ub3RpZmljYXRpb25zRG9tYWluLmJ1bGtSZWFkTm90aWZpY2F0aW9ucyhwYXJhbXMpO1xuICAgIH1cbiAgICBcbiAgICBidWxrUmVhZE5vdGlmaWNhdGlvbnMyKHBhcmFtczogWC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZE5vdGlmaWNhdGlvbnNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLm5vdGlmaWNhdGlvbnNEb21haW4uYnVsa1JlYWROb3RpZmljYXRpb25zMihwYXJhbXMpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFBhdGhzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfcGF0aHNEb21haW46IFguUGF0aHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBwYXRoc0RvbWFpbigpOiBYLlBhdGhzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wYXRoc0RvbWFpbikge1xuICAgICAgICAgICAgdGhpcy5fcGF0aHNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlBhdGhzRG9tYWluKTtcbiAgICAgICAgfVxuICAgIFxuICAgICAgICByZXR1cm4gdGhpcy5fcGF0aHNEb21haW47XG4gICAgfVxuXG4gICAgYnVsa0RlbGV0ZVBhdGhzKHBhcmFtczogWC5CdWxrRGVsZXRlUGF0aHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrRGVsZXRlUGF0aHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5idWxrRGVsZXRlUGF0aHMocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFBhdGhzKHBhcmFtczogWC5CdWxrUmVhZFBhdGhzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFBhdGhzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXRoc0RvbWFpbi5idWxrUmVhZFBhdGhzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkUGF0aHMyKHBhcmFtczogWC5CdWxrUmVhZFBhdGhzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQYXRoc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF0aHNEb21haW4uYnVsa1JlYWRQYXRoczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBjcmVhdGVQYXRoKGJvZHk6IFguQ3JlYXRlUGF0aEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLmNyZWF0ZVBhdGgoYm9keSk7XG4gICAgfVxuXG4gICAgcmVhZFBhdGgocGF0aElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLnJlYWRQYXRoKHBhdGhJZCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRQYXRoMihwYXRoSWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLnJlYWRQYXRoMihwYXRoSWQpO1xuICAgIH1cblxuICAgIHVwZGF0ZVBhdGgocGF0aElkOiBhbnksIGJvZHk6IFguVXBkYXRlUGF0aEJvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlUGF0aFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhdGhzRG9tYWluLnVwZGF0ZVBhdGgocGF0aElkLCBib2R5KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBQYXltZW50IENhcmRzIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfcGF5bWVudF9jYXJkc0RvbWFpbjogWC5QYXltZW50Q2FyZHNEb21haW47XG4gICAgXG4gICAgcHVibGljIGdldCBwYXltZW50X2NhcmRzRG9tYWluKCk6IFguUGF5bWVudENhcmRzRG9tYWluIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wYXltZW50X2NhcmRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9wYXltZW50X2NhcmRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5QYXltZW50Q2FyZHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9wYXltZW50X2NhcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGFzRGVmYXVsdE1hcmtQYXltZW50Y2FyZChwYXltZW50Q2FyZElkOiBhbnkpOiBPYnNlcnZhYmxlPFguQXNEZWZhdWx0TWFya1BheW1lbnRjYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5hc0RlZmF1bHRNYXJrUGF5bWVudGNhcmQocGF5bWVudENhcmRJZCk7XG4gICAgfVxuXG4gICAgYnVsa1JlYWRQYXltZW50Y2FyZHMoKTogRGF0YVN0YXRlPFguQnVsa1JlYWRQYXltZW50Y2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uYnVsa1JlYWRQYXltZW50Y2FyZHMoKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRQYXltZW50Y2FyZHMyKCk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFBheW1lbnRjYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5idWxrUmVhZFBheW1lbnRjYXJkczIoKTtcbiAgICB9XG5cbiAgICBjcmVhdGVQYXltZW50Y2FyZChib2R5OiBYLkNyZWF0ZVBheW1lbnRjYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVQYXltZW50Y2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4uY3JlYXRlUGF5bWVudGNhcmQoYm9keSk7XG4gICAgfVxuXG4gICAgZGVsZXRlUGF5bWVudGNhcmQocGF5bWVudENhcmRJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZVBheW1lbnRjYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGF5bWVudF9jYXJkc0RvbWFpbi5kZWxldGVQYXltZW50Y2FyZChwYXltZW50Q2FyZElkKTtcbiAgICB9XG5cbiAgICBwYXlXaXRoRGVmYXVsdFBheW1lbnRDYXJkKGJvZHk6IFguUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZEJvZHkpOiBPYnNlcnZhYmxlPFguUGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4ucGF5V2l0aERlZmF1bHRQYXltZW50Q2FyZChib2R5KTtcbiAgICB9XG5cbiAgICByZW5kZXJQYXltZW50Q2FyZFdpZGdldCgpOiBEYXRhU3RhdGU8WC5SZW5kZXJQYXltZW50Q2FyZFdpZGdldFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4ucmVuZGVyUGF5bWVudENhcmRXaWRnZXQoKTtcbiAgICB9XG4gICAgXG4gICAgcmVuZGVyUGF5bWVudENhcmRXaWRnZXQyKCk6IE9ic2VydmFibGU8WC5SZW5kZXJQYXltZW50Q2FyZFdpZGdldFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRfY2FyZHNEb21haW4ucmVuZGVyUGF5bWVudENhcmRXaWRnZXQyKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUGF5bWVudHMgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF9wYXltZW50c0RvbWFpbjogWC5QYXltZW50c0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHBheW1lbnRzRG9tYWluKCk6IFguUGF5bWVudHNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3BheW1lbnRzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9wYXltZW50c0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguUGF5bWVudHNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9wYXltZW50c0RvbWFpbjtcbiAgICB9XG5cbiAgICB1cGRhdGVQYXltZW50U3RhdHVzKGJvZHk6IFguVXBkYXRlUGF5bWVudFN0YXR1c0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlUGF5bWVudFN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnBheW1lbnRzRG9tYWluLnVwZGF0ZVBheW1lbnRTdGF0dXMoYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVjYWxsIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfcmVjYWxsRG9tYWluOiBYLlJlY2FsbERvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHJlY2FsbERvbWFpbigpOiBYLlJlY2FsbERvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fcmVjYWxsRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl9yZWNhbGxEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlJlY2FsbERvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3JlY2FsbERvbWFpbjtcbiAgICB9XG5cbiAgICBjcmVhdGVSZWNhbGxTZXNzaW9uKGJvZHk6IFguQ3JlYXRlUmVjYWxsU2Vzc2lvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUmVjYWxsU2Vzc2lvblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLnJlY2FsbERvbWFpbi5jcmVhdGVSZWNhbGxTZXNzaW9uKGJvZHkpO1xuICAgIH1cblxuICAgIHJlYWRSZWNhbGxTdW1tYXJ5KCk6IERhdGFTdGF0ZTxYLlJlYWRSZWNhbGxTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMucmVjYWxsRG9tYWluLnJlYWRSZWNhbGxTdW1tYXJ5KCk7XG4gICAgfVxuICAgIFxuICAgIHJlYWRSZWNhbGxTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZFJlY2FsbFN1bW1hcnlSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5yZWNhbGxEb21haW4ucmVhZFJlY2FsbFN1bW1hcnkyKCk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU3Vic2NyaXB0aW9uIE1hbmFnZW1lbnQgZG9tYWluXG4gICAgICovXG4gICAgcHJpdmF0ZSBfc3Vic2NyaXB0aW9uc0RvbWFpbjogWC5TdWJzY3JpcHRpb25zRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgc3Vic2NyaXB0aW9uc0RvbWFpbigpOiBYLlN1YnNjcmlwdGlvbnNEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3N1YnNjcmlwdGlvbnNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3N1YnNjcmlwdGlvbnNEb21haW4gPSB0aGlzLmluamVjdG9yLmdldChYLlN1YnNjcmlwdGlvbnNEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl9zdWJzY3JpcHRpb25zRG9tYWluO1xuICAgIH1cblxuICAgIGNoYW5nZVN1YnNjcmlwdGlvbihib2R5OiBYLkNoYW5nZVN1YnNjcmlwdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuc3Vic2NyaXB0aW9uc0RvbWFpbi5jaGFuZ2VTdWJzY3JpcHRpb24oYm9keSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVGFza3MgTWFuYWdlbWVudCBkb21haW5cbiAgICAgKi9cbiAgICBwcml2YXRlIF90YXNrc0RvbWFpbjogWC5UYXNrc0RvbWFpbjtcbiAgICBcbiAgICBwdWJsaWMgZ2V0IHRhc2tzRG9tYWluKCk6IFguVGFza3NEb21haW4ge1xuICAgICAgICBpZiAoIXRoaXMuX3Rhc2tzRG9tYWluKSB7XG4gICAgICAgICAgICB0aGlzLl90YXNrc0RvbWFpbiA9IHRoaXMuaW5qZWN0b3IuZ2V0KFguVGFza3NEb21haW4pO1xuICAgICAgICB9XG4gICAgXG4gICAgICAgIHJldHVybiB0aGlzLl90YXNrc0RvbWFpbjtcbiAgICB9XG5cbiAgICBidWxrUmVhZFRhc2tzKHBhcmFtczogWC5CdWxrUmVhZFRhc2tzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy50YXNrc0RvbWFpbi5idWxrUmVhZFRhc2tzKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkVGFza3MyKHBhcmFtczogWC5CdWxrUmVhZFRhc2tzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMudGFza3NEb21haW4uYnVsa1JlYWRUYXNrczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICBidWxrUmVhZFRhc2tCaW5zKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy50YXNrc0RvbWFpbi5idWxrUmVhZFRhc2tCaW5zKHBhcmFtcyk7XG4gICAgfVxuICAgIFxuICAgIGJ1bGtSZWFkVGFza0JpbnMyKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMudGFza3NEb21haW4uYnVsa1JlYWRUYXNrQmluczIocGFyYW1zKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBXb3JkcyBNYW5hZ2VtZW50IGRvbWFpblxuICAgICAqL1xuICAgIHByaXZhdGUgX3dvcmRzRG9tYWluOiBYLldvcmRzRG9tYWluO1xuICAgIFxuICAgIHB1YmxpYyBnZXQgd29yZHNEb21haW4oKTogWC5Xb3Jkc0RvbWFpbiB7XG4gICAgICAgIGlmICghdGhpcy5fd29yZHNEb21haW4pIHtcbiAgICAgICAgICAgIHRoaXMuX3dvcmRzRG9tYWluID0gdGhpcy5pbmplY3Rvci5nZXQoWC5Xb3Jkc0RvbWFpbik7XG4gICAgICAgIH1cbiAgICBcbiAgICAgICAgcmV0dXJuIHRoaXMuX3dvcmRzRG9tYWluO1xuICAgIH1cblxuICAgIGJ1bGtSZWFkV29yZHMocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkV29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLndvcmRzRG9tYWluLmJ1bGtSZWFkV29yZHMocGFyYW1zKTtcbiAgICB9XG4gICAgXG4gICAgYnVsa1JlYWRXb3JkczIocGFyYW1zOiBYLkJ1bGtSZWFkV29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy53b3Jkc0RvbWFpbi5idWxrUmVhZFdvcmRzMihwYXJhbXMpO1xuICAgIH1cblxufSIsIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbmltcG9ydCB7IE5nTW9kdWxlLCBNb2R1bGVXaXRoUHJvdmlkZXJzIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBIdHRwQ2xpZW50TW9kdWxlIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuXG4vKiogRG9tYWlucyAqL1xuaW1wb3J0IHsgQWNjb3VudFNldHRpbmdzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2FjY291bnRfc2V0dGluZ3MvaW5kZXgnO1xuaW1wb3J0IHsgQWNjb3VudHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvYWNjb3VudHMvaW5kZXgnO1xuaW1wb3J0IHsgQXR0ZW1wdFN0YXRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2F0dGVtcHRfc3RhdHMvaW5kZXgnO1xuaW1wb3J0IHsgQXR0ZW1wdHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvYXR0ZW1wdHMvaW5kZXgnO1xuaW1wb3J0IHsgQXV0aFRva2Vuc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9hdXRoX3Rva2Vucy9pbmRleCc7XG5pbXBvcnQgeyBDYXJkc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9jYXJkcy9pbmRleCc7XG5pbXBvcnQgeyBDYXRlZ29yaWVzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2NhdGVnb3JpZXMvaW5kZXgnO1xuaW1wb3J0IHsgQ29udGFjdHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvY29udGFjdHMvaW5kZXgnO1xuaW1wb3J0IHsgRG9uYXRpb25zRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2RvbmF0aW9ucy9pbmRleCc7XG5pbXBvcnQgeyBFeHRlcm5hbEFwcHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvZXh0ZXJuYWxfYXBwcy9pbmRleCc7XG5pbXBvcnQgeyBGb2N1c1JlY29yZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvZm9jdXNfcmVjb3Jkcy9pbmRleCc7XG5pbXBvcnQgeyBGcmFnbWVudEhhc2h0YWdzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZyYWdtZW50X2hhc2h0YWdzL2luZGV4JztcbmltcG9ydCB7IEZyYWdtZW50V29yZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvZnJhZ21lbnRfd29yZHMvaW5kZXgnO1xuaW1wb3J0IHsgRnJhZ21lbnRzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2ZyYWdtZW50cy9pbmRleCc7XG5pbXBvcnQgeyBHZW9tZXRyaWVzRG9tYWluIH0gZnJvbSAnLi9kb21haW5zL2dlb21ldHJpZXMvaW5kZXgnO1xuaW1wb3J0IHsgSGFzaHRhZ3NEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvaGFzaHRhZ3MvaW5kZXgnO1xuaW1wb3J0IHsgSW50ZXJuYWxEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvaW50ZXJuYWwvaW5kZXgnO1xuaW1wb3J0IHsgSW52b2ljZXNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvaW52b2ljZXMvaW5kZXgnO1xuaW1wb3J0IHsgTGlua3NEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvbGlua3MvaW5kZXgnO1xuaW1wb3J0IHsgTWVkaWFpdGVtc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9tZWRpYWl0ZW1zL2luZGV4JztcbmltcG9ydCB7IE5vdGlmaWNhdGlvbnNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvbm90aWZpY2F0aW9ucy9pbmRleCc7XG5pbXBvcnQgeyBQYXRoc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9wYXRocy9pbmRleCc7XG5pbXBvcnQgeyBQYXltZW50Q2FyZHNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcGF5bWVudF9jYXJkcy9pbmRleCc7XG5pbXBvcnQgeyBQYXltZW50c0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy9wYXltZW50cy9pbmRleCc7XG5pbXBvcnQgeyBSZWNhbGxEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvcmVjYWxsL2luZGV4JztcbmltcG9ydCB7IFN1YnNjcmlwdGlvbnNEb21haW4gfSBmcm9tICcuL2RvbWFpbnMvc3Vic2NyaXB0aW9ucy9pbmRleCc7XG5pbXBvcnQgeyBUYXNrc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy90YXNrcy9pbmRleCc7XG5pbXBvcnQgeyBXb3Jkc0RvbWFpbiB9IGZyb20gJy4vZG9tYWlucy93b3Jkcy9pbmRleCc7XG5cbi8qKiBTZXJ2aWNlcyAqL1xuLy8gaW1wb3J0IHtcbi8vICAgQVBJU2VydmljZSxcbi8vICAgQ2xpZW50U2VydmljZSxcbi8vICAgLy8gQ29uZmlnU2VydmljZSxcbi8vICAgQ29uZmlnXG4vLyB9IGZyb20gJy4vc2VydmljZXMvaW5kZXgnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBBUElTZXJ2aWNlIH0gZnJvbSAnLi9zZXJ2aWNlcy9hcGkuc2VydmljZSc7XG5pbXBvcnQgeyBDb25maWcgfSBmcm9tICcuL3NlcnZpY2VzL2NvbmZpZy5zZXJ2aWNlJztcblxuXG4vLyBleHBvcnQgZnVuY3Rpb24gY29uZmlnRmFjdG9yeShjb25maWc6IENvbmZpZykge1xuLy8gICByZXR1cm4gbmV3IENvbmZpZ1NlcnZpY2UoY29uZmlnKTtcbi8vIH1cblxuQE5nTW9kdWxlKHtcbiAgaW1wb3J0czogW0h0dHBDbGllbnRNb2R1bGVdLFxuICBwcm92aWRlcnM6IFtcbiAgICBDbGllbnRTZXJ2aWNlLFxuXG4gICAgLy8gRG9tYWluc1xuICAgIEFjY291bnRTZXR0aW5nc0RvbWFpbixcbiAgICBBY2NvdW50c0RvbWFpbixcbiAgICBBdHRlbXB0U3RhdHNEb21haW4sXG4gICAgQXR0ZW1wdHNEb21haW4sXG4gICAgQXV0aFRva2Vuc0RvbWFpbixcbiAgICBDYXJkc0RvbWFpbixcbiAgICBDYXRlZ29yaWVzRG9tYWluLFxuICAgIENvbnRhY3RzRG9tYWluLFxuICAgIERvbmF0aW9uc0RvbWFpbixcbiAgICBFeHRlcm5hbEFwcHNEb21haW4sXG4gICAgRm9jdXNSZWNvcmRzRG9tYWluLFxuICAgIEZyYWdtZW50SGFzaHRhZ3NEb21haW4sXG4gICAgRnJhZ21lbnRXb3Jkc0RvbWFpbixcbiAgICBGcmFnbWVudHNEb21haW4sXG4gICAgR2VvbWV0cmllc0RvbWFpbixcbiAgICBIYXNodGFnc0RvbWFpbixcbiAgICBJbnRlcm5hbERvbWFpbixcbiAgICBJbnZvaWNlc0RvbWFpbixcbiAgICBMaW5rc0RvbWFpbixcbiAgICBNZWRpYWl0ZW1zRG9tYWluLFxuICAgIE5vdGlmaWNhdGlvbnNEb21haW4sXG4gICAgUGF0aHNEb21haW4sXG4gICAgUGF5bWVudENhcmRzRG9tYWluLFxuICAgIFBheW1lbnRzRG9tYWluLFxuICAgIFJlY2FsbERvbWFpbixcbiAgICBTdWJzY3JpcHRpb25zRG9tYWluLFxuICAgIFRhc2tzRG9tYWluLFxuICAgIFdvcmRzRG9tYWluLFxuXG4gICAgLy8gRmFjYWRlXG4gICAgQVBJU2VydmljZSxcbiAgXVxufSlcbmV4cG9ydCBjbGFzcyBDbGllbnRNb2R1bGUge1xuICAgIHN0YXRpYyBmb3JSb290KGNvbmZpZzogQ29uZmlnKTogTW9kdWxlV2l0aFByb3ZpZGVycyB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBuZ01vZHVsZTogQ2xpZW50TW9kdWxlLFxuICAgICAgICAgICAgcHJvdmlkZXJzOiBbXG4gICAgICAgICAgICAgICAgLy8ge1xuICAgICAgICAgICAgICAgIC8vICAgICBwcm92aWRlOiBDb25maWdTZXJ2aWNlLFxuICAgICAgICAgICAgICAgIC8vICAgICB1c2VGYWN0b3J5OiBjb25maWdGYWN0b3J5KGNvbmZpZylcbiAgICAgICAgICAgICAgICAvLyB9LCxcbiAgICAgICAgICAgICAgICB7cHJvdmlkZTogJ2NvbmZpZycsIHVzZVZhbHVlOiBjb25maWd9XG4gICAgICAgICAgICBdXG4gICAgICAgIH07XG4gICAgfVxufSIsIi8qKlxuICogR2VuZXJhdGVkIGJ1bmRsZSBpbmRleC4gRG8gbm90IGVkaXQuXG4gKi9cblxuZXhwb3J0ICogZnJvbSAnLi9wdWJsaWNfYXBpJztcblxuZXhwb3J0IHtDb25maWcgYXMgw4nCtWF9IGZyb20gJy4vc2VydmljZXMvY29uZmlnLnNlcnZpY2UnOyJdLCJuYW1lcyI6WyJfLmhhcyIsIl8uaXNFbXB0eSIsIlguQWNjb3VudFNldHRpbmdzRG9tYWluIiwiWC5BY2NvdW50c0RvbWFpbiIsIlguQXR0ZW1wdFN0YXRzRG9tYWluIiwiWC5BdHRlbXB0c0RvbWFpbiIsIlguQXV0aFRva2Vuc0RvbWFpbiIsIlguQ2FyZHNEb21haW4iLCJYLkNhdGVnb3JpZXNEb21haW4iLCJYLkNvbnRhY3RzRG9tYWluIiwiWC5Eb25hdGlvbnNEb21haW4iLCJYLkV4dGVybmFsQXBwc0RvbWFpbiIsIlguRm9jdXNSZWNvcmRzRG9tYWluIiwiWC5GcmFnbWVudEhhc2h0YWdzRG9tYWluIiwiWC5GcmFnbWVudFdvcmRzRG9tYWluIiwiWC5GcmFnbWVudHNEb21haW4iLCJYLkdlb21ldHJpZXNEb21haW4iLCJYLkhhc2h0YWdzRG9tYWluIiwiWC5JbnRlcm5hbERvbWFpbiIsIlguSW52b2ljZXNEb21haW4iLCJYLkxpbmtzRG9tYWluIiwiWC5NZWRpYWl0ZW1zRG9tYWluIiwiWC5Ob3RpZmljYXRpb25zRG9tYWluIiwiWC5QYXRoc0RvbWFpbiIsIlguUGF5bWVudENhcmRzRG9tYWluIiwiWC5QYXltZW50c0RvbWFpbiIsIlguUmVjYWxsRG9tYWluIiwiWC5TdWJzY3JpcHRpb25zRG9tYWluIiwiWC5UYXNrc0RvbWFpbiIsIlguV29yZHNEb21haW4iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7SUFtQ0UsWUFBc0MsTUFBYyxFQUFVLElBQWdCO1FBQXhDLFdBQU0sR0FBTixNQUFNLENBQVE7UUFBVSxTQUFJLEdBQUosSUFBSSxDQUFZOzs7O1FBZDlFLFVBQUssR0FBRyxJQUFJLEdBQUcsRUFBc0IsQ0FBQztRQUtyQixxQkFBZ0IsR0FBVyxZQUFZLENB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