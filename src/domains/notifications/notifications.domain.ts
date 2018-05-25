/**
 * Notification Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import * as X from './notifications.models';

@Injectable()
export class NotificationsDomain {
    constructor(private client: ClientService) {}

    /**
     * Acknowledge Notification
     * -------------
     *
     * Acknowledge Notification
     */
    public acknowledgeNotification(notificationId: any): Observable<X.AcknowledgeNotificationResponse> {
        return this.client
            .put<X.AcknowledgeNotificationResponse>(`/notifications/${notificationId}/acknowledge/`, {})
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * List Notifications
     * -------------
     *
     * List Notifications
     */
    public bulkReadNotifications(params: X.BulkReadNotificationsQuery): DataState<X.BulkReadNotificationsResponse> {
        return this.client.getDataState<X.BulkReadNotificationsResponse>('/notifications/', { params });
    }

}