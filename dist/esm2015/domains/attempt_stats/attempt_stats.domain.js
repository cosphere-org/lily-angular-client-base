/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Attempt Stats Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
export class AttemptStatsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Attempt Stats
     * -------------
     *
     * List Attempt Stats by filtering existing ones.
     */
    bulkReadAttemptstats(params) {
        return this.client.getDataState('/recall/attempt_stats/', { params, authorizationRequired: true });
    }
    bulkReadAttemptstats2(params) {
        return this.client.get('/recall/attempt_stats/', { params, authorizationRequired: true });
    }
    /**
     * Create Attempt Stat
     * -------------
     *
     * Create Attempt Stat which stores information about basis statistics of a particular recall attempt.
     */
    createAttemptstat(body) {
        return this.client
            .post('/recall/attempt_stats/', body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
    /**
     * Create External Attempt Stat
     * -------------
     *
     * Create External Attempt Stat meaning one which was rendered elsewhere in any of the multiple CoSphere apps.
     */
    createExternalAttemptStat(body) {
        return this.client
            .post('/recall/attempt_stats/external/', body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
}
AttemptStatsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
AttemptStatsDomain.ctorParameters = () => [
    { type: ClientService }
];

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXR0ZW1wdF9zdGF0cy5kb21haW4uanMiLCJzb3VyY2VSb290Ijoibmc6Ly9AY29zcGhlcmUvY2xpZW50LyIsInNvdXJjZXMiOlsiZG9tYWlucy9hdHRlbXB0X3N0YXRzL2F0dGVtcHRfc3RhdHMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBTTlELE1BQU07SUFDRixZQUFvQixNQUFxQjtRQUFyQixXQUFNLEdBQU4sTUFBTSxDQUFlO0lBQUcsQ0FBQztJQUU3Qzs7Ozs7T0FLRztJQUNJLG9CQUFvQixDQUFDLE1BQW1DO1FBQzNELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBaUMsd0JBQXdCLEVBQUUsRUFBRSxNQUFNLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUN2SSxDQUFDO0lBRU0scUJBQXFCLENBQUMsTUFBbUM7UUFDNUQsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFpQyx3QkFBd0IsRUFBRSxFQUFFLE1BQU0sRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQzlILENBQUM7SUFFRDs7Ozs7T0FLRztJQUNJLGlCQUFpQixDQUFDLElBQTZCO1FBQ2xELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBOEIsd0JBQXdCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDbEcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0kseUJBQXlCLENBQUMsSUFBcUM7UUFDbEUsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUFzQyxpQ0FBaUMsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUNuSCxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMxQyxDQUFDOzs7WUF4Q0osVUFBVTs7OztZQUxGLGFBQWEiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEF0dGVtcHQgU3RhdHMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vYXR0ZW1wdF9zdGF0cy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQXR0ZW1wdFN0YXRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgQXR0ZW1wdCBTdGF0c1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgQXR0ZW1wdCBTdGF0cyBieSBmaWx0ZXJpbmcgZXhpc3Rpbmcgb25lcy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRBdHRlbXB0c3RhdHMocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEF0dGVtcHRzdGF0c1Jlc3BvbnNlPignL3JlY2FsbC9hdHRlbXB0X3N0YXRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEF0dGVtcHRzdGF0czIocGFyYW1zOiBYLkJ1bGtSZWFkQXR0ZW1wdHN0YXRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRBdHRlbXB0c3RhdHNSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdF9zdGF0cy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBBdHRlbXB0IFN0YXRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgQXR0ZW1wdCBTdGF0IHdoaWNoIHN0b3JlcyBpbmZvcm1hdGlvbiBhYm91dCBiYXNpcyBzdGF0aXN0aWNzIG9mIGEgcGFydGljdWxhciByZWNhbGwgYXR0ZW1wdC5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlQXR0ZW1wdHN0YXQoYm9keTogWC5DcmVhdGVBdHRlbXB0c3RhdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXR0ZW1wdHN0YXRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlQXR0ZW1wdHN0YXRSZXNwb25zZT4oJy9yZWNhbGwvYXR0ZW1wdF9zdGF0cy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBFeHRlcm5hbCBBdHRlbXB0IFN0YXRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgRXh0ZXJuYWwgQXR0ZW1wdCBTdGF0IG1lYW5pbmcgb25lIHdoaWNoIHdhcyByZW5kZXJlZCBlbHNld2hlcmUgaW4gYW55IG9mIHRoZSBtdWx0aXBsZSBDb1NwaGVyZSBhcHBzLlxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0KGJvZHk6IFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdEJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlRXh0ZXJuYWxBdHRlbXB0U3RhdFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVFeHRlcm5hbEF0dGVtcHRTdGF0UmVzcG9uc2U+KCcvcmVjYWxsL2F0dGVtcHRfc3RhdHMvZXh0ZXJuYWwvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iXX0=