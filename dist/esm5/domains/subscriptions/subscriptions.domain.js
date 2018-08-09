/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Subscription Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
var SubscriptionsDomain = /** @class */ (function () {
    function SubscriptionsDomain(client) {
        this.client = client;
    }
    /**
     * Request a subscription change
     * -------------
     *
     * Whenever the user wants to change her subscription it must happen through this endpoint. It's still possible that the subscription will change without user asking for it, but that can happen when downgrading due to missing payment.
     */
    SubscriptionsDomain.prototype.changeSubscription = function (body) {
        return this.client
            .put('/payments/subscription/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    SubscriptionsDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    SubscriptionsDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return SubscriptionsDomain;
}());
export { SubscriptionsDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic3Vic2NyaXB0aW9ucy5kb21haW4uanMiLCJzb3VyY2VSb290Ijoibmc6Ly9AY29zcGhlcmUvY2xpZW50LyIsInNvdXJjZXMiOlsiZG9tYWlucy9zdWJzY3JpcHRpb25zL3N1YnNjcmlwdGlvbnMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBSzlEO0lBRUksNkJBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7SUFBRyxDQUFDO0lBRTdDOzs7OztPQUtHO0lBQ0ksZ0RBQWtCLEdBQXpCLFVBQTBCLElBQThCO1FBQ3BELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLEdBQUcsQ0FBK0IseUJBQXlCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDbkcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7O2dCQWRKLFVBQVU7Ozs7Z0JBTEYsYUFBYTs7SUFxQnRCLDBCQUFDO0NBQUEsQUFoQkQsSUFnQkM7U0FmWSxtQkFBbUIiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIFN1YnNjcmlwdGlvbiBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9zdWJzY3JpcHRpb25zLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBTdWJzY3JpcHRpb25zRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIFJlcXVlc3QgYSBzdWJzY3JpcHRpb24gY2hhbmdlXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogV2hlbmV2ZXIgdGhlIHVzZXIgd2FudHMgdG8gY2hhbmdlIGhlciBzdWJzY3JpcHRpb24gaXQgbXVzdCBoYXBwZW4gdGhyb3VnaCB0aGlzIGVuZHBvaW50LiBJdCdzIHN0aWxsIHBvc3NpYmxlIHRoYXQgdGhlIHN1YnNjcmlwdGlvbiB3aWxsIGNoYW5nZSB3aXRob3V0IHVzZXIgYXNraW5nIGZvciBpdCwgYnV0IHRoYXQgY2FuIGhhcHBlbiB3aGVuIGRvd25ncmFkaW5nIGR1ZSB0byBtaXNzaW5nIHBheW1lbnQuXG4gICAgICovXG4gICAgcHVibGljIGNoYW5nZVN1YnNjcmlwdGlvbihib2R5OiBYLkNoYW5nZVN1YnNjcmlwdGlvbkJvZHkpOiBPYnNlcnZhYmxlPFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguQ2hhbmdlU3Vic2NyaXB0aW9uUmVzcG9uc2U+KCcvcGF5bWVudHMvc3Vic2NyaXB0aW9uLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59Il19