/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Payment Cards Management Domain Models
 */
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/.venv/src/lily/lily/base/serializers.py/#lines-158
 */
export interface AsDefaultMarkPaymentcardResponse {
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment_card.py/#lines-75
 */
export declare enum BulkReadPaymentcardsResponseCurrency {
    PLN = "PLN",
}
export declare enum BulkReadPaymentcardsResponseProductType {
    DONATION = "DONATION",
    SUBSCRIPTION_LEARNER_MONTHLY = "SUBSCRIPTION_LEARNER_MONTHLY",
    SUBSCRIPTION_LEARNER_YEARLY = "SUBSCRIPTION_LEARNER_YEARLY",
    SUBSCRIPTION_MENTOR_MONTHLY = "SUBSCRIPTION_MENTOR_MONTHLY",
    SUBSCRIPTION_MENTOR_YEARLY = "SUBSCRIPTION_MENTOR_YEARLY",
}
export declare enum BulkReadPaymentcardsResponseStatus {
    CANCELED = "CANCELED",
    COMPLETED = "COMPLETED",
    NEW = "NEW",
    PENDING = "PENDING",
    REJECTED = "REJECTED",
}
export interface BulkReadPaymentcardsResponseEntity {
    expiration_month?: number;
    expiration_year?: number;
    expired: boolean;
    id?: number;
    is_default?: boolean;
    is_fully_defined: boolean;
    masked_number: string;
    payments: {
        amount: string;
        created_timestamp: number;
        display_amount: string;
        product: {
            currency?: BulkReadPaymentcardsResponseCurrency;
            display_price: string;
            name: string;
            price?: string;
            product_type: BulkReadPaymentcardsResponseProductType;
        };
        status?: BulkReadPaymentcardsResponseStatus;
        status_ledger?: Object;
    }[];
}
export interface BulkReadPaymentcardsResponse {
    payment_cards: BulkReadPaymentcardsResponseEntity[];
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/views/payment_card.py/#lines-52
 */
export interface CreatePaymentcardBody {
    expiration_month: number;
    expiration_year: number;
    mark_as_default?: boolean;
    masked_number: string;
    token: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment_card.py/#lines-9
 */
export declare enum CreatePaymentcardResponseCurrency {
    PLN = "PLN",
}
export declare enum CreatePaymentcardResponseProductType {
    DONATION = "DONATION",
    SUBSCRIPTION_LEARNER_MONTHLY = "SUBSCRIPTION_LEARNER_MONTHLY",
    SUBSCRIPTION_LEARNER_YEARLY = "SUBSCRIPTION_LEARNER_YEARLY",
    SUBSCRIPTION_MENTOR_MONTHLY = "SUBSCRIPTION_MENTOR_MONTHLY",
    SUBSCRIPTION_MENTOR_YEARLY = "SUBSCRIPTION_MENTOR_YEARLY",
}
export declare enum CreatePaymentcardResponseStatus {
    CANCELED = "CANCELED",
    COMPLETED = "COMPLETED",
    NEW = "NEW",
    PENDING = "PENDING",
    REJECTED = "REJECTED",
}
export interface CreatePaymentcardResponse {
    expiration_month?: number;
    expiration_year?: number;
    expired: boolean;
    id?: number;
    is_default?: boolean;
    is_fully_defined: boolean;
    masked_number: string;
    payments: {
        amount: string;
        created_timestamp: number;
        display_amount: string;
        product: {
            currency?: CreatePaymentcardResponseCurrency;
            display_price: string;
            name: string;
            price?: string;
            product_type: CreatePaymentcardResponseProductType;
        };
        status?: CreatePaymentcardResponseStatus;
        status_ledger?: Object;
    }[];
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/.venv/src/lily/lily/base/serializers.py/#lines-158
 */
export interface DeletePaymentcardResponse {
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/views/payment_card.py/#lines-204
 */
export interface PayWithDefaultPaymentCardBody {
    payment_token: string;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/serializers/payment.py/#lines-9
 */
export declare enum PayWithDefaultPaymentCardResponseCurrency {
    PLN = "PLN",
}
export declare enum PayWithDefaultPaymentCardResponseProductType {
    DONATION = "DONATION",
    SUBSCRIPTION_LEARNER_MONTHLY = "SUBSCRIPTION_LEARNER_MONTHLY",
    SUBSCRIPTION_LEARNER_YEARLY = "SUBSCRIPTION_LEARNER_YEARLY",
    SUBSCRIPTION_MENTOR_MONTHLY = "SUBSCRIPTION_MENTOR_MONTHLY",
    SUBSCRIPTION_MENTOR_YEARLY = "SUBSCRIPTION_MENTOR_YEARLY",
}
export declare enum PayWithDefaultPaymentCardResponseStatus {
    CANCELED = "CANCELED",
    COMPLETED = "COMPLETED",
    NEW = "NEW",
    PENDING = "PENDING",
    REJECTED = "REJECTED",
}
export interface PayWithDefaultPaymentCardResponse {
    amount: string;
    created_timestamp: number;
    display_amount: string;
    product: {
        currency?: PayWithDefaultPaymentCardResponseCurrency;
        display_price: string;
        name: string;
        price?: string;
        product_type: PayWithDefaultPaymentCardResponseProductType;
    };
    status?: PayWithDefaultPaymentCardResponseStatus;
    status_ledger?: Object;
}
/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/69bb55b04713846fc3aa1a1c300a8a9ed207b2d3/cosphere_auth_service/payment/models/payu.py/#lines-313
 */
export interface RenderPaymentCardWidgetResponse {
    currency_code: string;
    customer_email?: string;
    customer_language: string;
    merchant_pos_id: string;
    recurring_payment: boolean;
    shop_name: string;
    sig: string;
    store_card: boolean;
    total_amount: string;
    widget_mode?: string;
}
