import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './notifications.models';
export declare class NotificationsDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Acknowledge Notification
     * -------------
     *
     * Acknowledge Notification
     */
    acknowledgeNotification(notificationId: any): Observable<X.AcknowledgeNotificationResponse>;
    /**
     * List Notifications
     * -------------
     *
     * List Notifications
     */
    bulkReadNotifications(params: X.BulkReadNotificationsQuery): DataState<X.BulkReadNotificationsResponseEntity[]>;
    bulkReadNotifications2(params: X.BulkReadNotificationsQuery): Observable<X.BulkReadNotificationsResponseEntity[]>;
}
