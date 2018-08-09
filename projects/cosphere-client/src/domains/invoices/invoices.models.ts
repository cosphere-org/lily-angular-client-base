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

export enum BulkReadInvoicesResponseCurrency {
    PLN = 'PLN',
}

export enum BulkReadInvoicesResponseProductType {
    DONATION = 'DONATION',
    SUBSCRIPTION_LEARNER_MONTHLY = 'SUBSCRIPTION_LEARNER_MONTHLY',
    SUBSCRIPTION_LEARNER_YEARLY = 'SUBSCRIPTION_LEARNER_YEARLY',
    SUBSCRIPTION_MENTOR_MONTHLY = 'SUBSCRIPTION_MENTOR_MONTHLY',
    SUBSCRIPTION_MENTOR_YEARLY = 'SUBSCRIPTION_MENTOR_YEARLY',
}

export interface BulkReadInvoicesResponseEntity {
    amount: string;
    created_timestamp: number;
    currency?: string;
    display_amount: string;
    id?: number;
    is_extension?: boolean;
    paid_till_timestamp: number;
    product: {
        currency?: BulkReadInvoicesResponseCurrency;
        display_price: string;
        name: string;
        price?: string;
        product_type: BulkReadInvoicesResponseProductType;
    };
    surplus_amount?: string;
    surplus_currency?: string;
    valid_till_timestamp: number;
}

export interface BulkReadInvoicesResponse {
    data: BulkReadInvoicesResponseEntity[];
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/09d74e1c1f6871739268cd74315b4f114592af2c/cosphere_auth_service/payment/views/invoice.py/#lines-51
 */

export interface CalculateDebtResponse {
    at__commands: Object;
    currency: string;
    display_owes: string;
    owes: number;
}