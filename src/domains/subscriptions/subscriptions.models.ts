/**
 * Subscription Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/subscription.py/#lines-28
 */

export enum ChangeSubscriptionBodySubscriptionType {
    FREE = 'FREE',
    SUBSCRIPTION_LEARNER_MONTHLY = 'SUBSCRIPTION_LEARNER_MONTHLY',
    SUBSCRIPTION_LEARNER_YEARLY = 'SUBSCRIPTION_LEARNER_YEARLY',
    SUBSCRIPTION_MENTOR_MONTHLY = 'SUBSCRIPTION_MENTOR_MONTHLY',
    SUBSCRIPTION_MENTOR_YEARLY = 'SUBSCRIPTION_MENTOR_YEARLY',
}

export interface ChangeSubscriptionBody {
    subscription_type: ChangeSubscriptionBodySubscriptionType;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/subscription.py/#lines-39
 */

export interface ChangeSubscriptionResponse {
    at__process: Object;
}