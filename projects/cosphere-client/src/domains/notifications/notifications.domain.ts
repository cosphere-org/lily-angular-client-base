/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */

/**
 * Notification Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';

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
            .put<X.AcknowledgeNotificationResponse>(`/notifications/${notificationId}/acknowledge/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }

    /**
     * List Notifications
     * -------------
     *
     * List Notifications
     */
    public bulkReadNotifications(params: X.BulkReadNotificationsQuery): DataState<X.BulkReadNotificationsResponseEntity[]> {
        return this.client.getDataState<X.BulkReadNotificationsResponseEntity[]>('/notifications/', { params, responseMap: 'notifications', authorizationRequired: true });
    }
    
    public bulkReadNotifications2(params: X.BulkReadNotificationsQuery): Observable<X.BulkReadNotificationsResponseEntity[]> {
        return this.client.get<X.BulkReadNotificationsResponseEntity[]>('/notifications/', { params, responseMap: 'notifications', authorizationRequired: true });
    }

}