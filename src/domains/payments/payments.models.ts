/**
 * Payments Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/payment/views/payment.py/#lines-15
 */

export interface UpdatePaymentStatusBody {
    order: {
        extOrderId: string;
        merchantPosId: string;
        status: string;
    };
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface UpdatePaymentStatusResponse {}