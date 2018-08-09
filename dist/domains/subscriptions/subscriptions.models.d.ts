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
export declare enum ChangeSubscriptionBodySubscriptionType {
    FREE = "FREE",
    SUBSCRIPTION_LEARNER_MONTHLY = "SUBSCRIPTION_LEARNER_MONTHLY",
    SUBSCRIPTION_LEARNER_YEARLY = "SUBSCRIPTION_LEARNER_YEARLY",
    SUBSCRIPTION_MENTOR_MONTHLY = "SUBSCRIPTION_MENTOR_MONTHLY",
    SUBSCRIPTION_MENTOR_YEARLY = "SUBSCRIPTION_MENTOR_YEARLY",
}
export interface ChangeSubscriptionBody {
    subscription_type: ChangeSubscriptionBodySubscriptionType;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/views/subscription.py/#lines-39
 */
export interface ChangeSubscriptionResponse {
    at__process: Object;
}
