/**
 * Notification Management Domain Models
 */

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/notification/views.py/#lines-77
 */

export interface BulkReadNotificationsQuery {
    acknowledged?: boolean;
    created_timestamp__gt?: number;
    limit?: number;
    offset?: number;
    updated_timestamp__gt?: number;
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/cosphere_fragment_service/notification/serializers.py/#lines-46
 */

export enum BulkReadNotificationsResponseKind {
    FRAGMENT_UPDATE = 'FRAGMENT_UPDATE',
}

export interface BulkReadNotificationsResponse {
    notifications: {
        acknowledged: boolean;
        created_timestamp: number;
        id?: number;
        kind: BulkReadNotificationsResponseKind;
        payload: Object;
        updated_timestamp: number;
    }[];
}

/**
 * https://bitbucket.org/goodai/cosphere-fragment-service/src/b7770a32394a95b057fb6ccd73a855eef5d41939/.venv/src/lily/lily/base/serializers.py/#lines-158
 */

export interface AcknowledgeNotificationResponse {}