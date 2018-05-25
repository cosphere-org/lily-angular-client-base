/**
 * Focus Records Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/focus/views.py/#lines-28
 */

export interface CreateFocusrecordBody {
    amount: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/focus/serializers.py/#lines-101
 */

export interface CreateFocusrecordResponse {
    amount: number;
    created_timestamp: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-auth-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_auth_service/focus/serializers.py/#lines-30
 */

export interface ReadFocusRecordSummaryResponse {
    average: number;
    ranking_absolute_top: {
        me: boolean;
        position: number;
        username: string;
        value: number;
    }[];
    ranking_relative_above: {
        me: boolean;
        position: number;
        username: string;
        value: number;
    }[];
    ranking_relative_below: {
        me: boolean;
        position: number;
        username: string;
        value: number;
    }[];
    time_series: {
        date: string;
        value: number;
    }[];
    total: number;
}