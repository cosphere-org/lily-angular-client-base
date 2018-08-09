/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Fragment Words Management Domain
 */
import { Injectable } from '@angular/core';
import { ClientService } from '../../services/client.service';
export class FragmentWordsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Words
     * -------------
     *
     * List Words
     */
    bulkReadFragmentWords(params) {
        return this.client.getDataState('/fragments/words/', { params, responseMap: 'data', authorizationRequired: true });
    }
    bulkReadFragmentWords2(params) {
        return this.client.get('/fragments/words/', { params, responseMap: 'data', authorizationRequired: true });
    }
    /**
     * List Published Words
     * -------------
     *
     * List Published Words
     */
    bulkReadPublishedFragmentWords(params) {
        return this.client.getDataState('/fragments/words/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
    bulkReadPublishedFragmentWords2(params) {
        return this.client.get('/fragments/words/published/', { params, responseMap: 'data', authorizationRequired: false });
    }
}
FragmentWordsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
FragmentWordsDomain.ctorParameters = () => [
    { type: ClientService }
];

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZnJhZ21lbnRfd29yZHMuZG9tYWluLmpzIiwic291cmNlUm9vdCI6Im5nOi8vQGNvc3BoZXJlL2NsaWVudC8iLCJzb3VyY2VzIjpbImRvbWFpbnMvZnJhZ21lbnRfd29yZHMvZnJhZ21lbnRfd29yZHMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUszQyxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sK0JBQStCLENBQUM7QUFNOUQsTUFBTTtJQUNGLFlBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7SUFBRyxDQUFDO0lBRTdDOzs7OztPQUtHO0lBQ0kscUJBQXFCLENBQUMsTUFBb0M7UUFDN0QsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUEwQyxtQkFBbUIsRUFBRSxFQUFFLE1BQU0sRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDaEssQ0FBQztJQUVNLHNCQUFzQixDQUFDLE1BQW9DO1FBQzlELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBMEMsbUJBQW1CLEVBQUUsRUFBRSxNQUFNLEVBQUUsV0FBVyxFQUFFLE1BQU0sRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ3ZKLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNJLDhCQUE4QixDQUFDLE1BQTZDO1FBQy9FLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBbUQsNkJBQTZCLEVBQUUsRUFBRSxNQUFNLEVBQUUsV0FBVyxFQUFFLE1BQU0sRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQyxDQUFDO0lBQ3BMLENBQUM7SUFFTSwrQkFBK0IsQ0FBQyxNQUE2QztRQUNoRixNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQW1ELDZCQUE2QixFQUFFLEVBQUUsTUFBTSxFQUFFLFdBQVcsRUFBRSxNQUFNLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUMsQ0FBQztJQUMzSyxDQUFDOzs7WUE5QkosVUFBVTs7OztZQUxGLGFBQWEiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZyYWdtZW50IFdvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZyYWdtZW50X3dvcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBGcmFnbWVudFdvcmRzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgV29yZHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFdvcmRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudFdvcmRzMihwYXJhbXM6IFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRGcmFnbWVudFdvcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvd29yZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFB1Ymxpc2hlZCBXb3Jkc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFdvcmRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRXb3JkcyhwYXJhbXM6IFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudFdvcmRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHMyKHBhcmFtczogWC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50V29yZHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy93b3Jkcy9wdWJsaXNoZWQvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuXG59Il19