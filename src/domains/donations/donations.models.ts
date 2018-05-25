/**
 * Donations Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/donation.py/#lines-180
 */

export interface CreateDonationBody {
    amount: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/serializers/payment.py/#lines-9
 */

export enum CreateDonationResponseCurrency {
    PLN = 'PLN',
}

export enum CreateDonationResponseProductType {
    DONATION = 'DONATION',
    SUBSCRIPTION_LEARNER_MONTHLY = 'SUBSCRIPTION_LEARNER_MONTHLY',
    SUBSCRIPTION_LEARNER_YEARLY = 'SUBSCRIPTION_LEARNER_YEARLY',
    SUBSCRIPTION_MENTOR_MONTHLY = 'SUBSCRIPTION_MENTOR_MONTHLY',
    SUBSCRIPTION_MENTOR_YEARLY = 'SUBSCRIPTION_MENTOR_YEARLY',
}

export enum CreateDonationResponseStatus {
    CANCELED = 'CANCELED',
    COMPLETED = 'COMPLETED',
    NEW = 'NEW',
    PENDING = 'PENDING',
    REJECTED = 'REJECTED',
}

export interface CreateDonationResponse {
    amount: string;
    created_timestamp: number;
    display_amount: string;
    product: {
        currency?: CreateDonationResponseCurrency;
        display_price: string;
        name: string;
        price?: string;
        product_type: CreateDonationResponseProductType;
    };
    status?: CreateDonationResponseStatus;
    status_ledger?: Object;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/donation.py/#lines-180
 */

export enum CreateDonationattemptBodyEvent {
    CLOSE = 'CLOSE',
    RECALL = 'RECALL',
    START = 'START',
}

export interface CreateDonationattemptBody {
    event: CreateDonationattemptBodyEvent;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/serializers/donation.py/#lines-8
 */

export enum CreateDonationattemptResponseEvent {
    CLOSE = 'CLOSE',
    RECALL = 'RECALL',
    START = 'START',
}

export interface CreateDonationattemptResponse {
    created_timestamp: number;
    event: CreateDonationattemptResponseEvent;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/donation.py/#lines-30
 */

export enum CheckIfCanAttemptDonationQueryEvent {
    CLOSE = 'CLOSE',
    RECALL = 'RECALL',
    START = 'START',
}

export interface CheckIfCanAttemptDonationQuery {
    event: CheckIfCanAttemptDonationQueryEvent;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/donation.py/#lines-34
 */

export interface CheckIfCanAttemptDonationResponse {
    can_attempt: boolean;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/donation.py/#lines-180
 */

export interface CreateAnonymousDonationBody {
    amount: number;
    email: string;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/serializers/payment.py/#lines-9
 */

export enum CreateAnonymousDonationResponseCurrency {
    PLN = 'PLN',
}

export enum CreateAnonymousDonationResponseProductType {
    DONATION = 'DONATION',
    SUBSCRIPTION_LEARNER_MONTHLY = 'SUBSCRIPTION_LEARNER_MONTHLY',
    SUBSCRIPTION_LEARNER_YEARLY = 'SUBSCRIPTION_LEARNER_YEARLY',
    SUBSCRIPTION_MENTOR_MONTHLY = 'SUBSCRIPTION_MENTOR_MONTHLY',
    SUBSCRIPTION_MENTOR_YEARLY = 'SUBSCRIPTION_MENTOR_YEARLY',
}

export enum CreateAnonymousDonationResponseStatus {
    CANCELED = 'CANCELED',
    COMPLETED = 'COMPLETED',
    NEW = 'NEW',
    PENDING = 'PENDING',
    REJECTED = 'REJECTED',
}

export interface CreateAnonymousDonationResponse {
    amount: string;
    created_timestamp: number;
    display_amount: string;
    product: {
        currency?: CreateAnonymousDonationResponseCurrency;
        display_price: string;
        name: string;
        price?: string;
        product_type: CreateAnonymousDonationResponseProductType;
    };
    status?: CreateAnonymousDonationResponseStatus;
    status_ledger?: Object;
}