/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Fragments Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
export class FragmentsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * List Remote Fragments
     * -------------
     *
     * List Remote Fragments
     */
    bulkReadFragments(params) {
        return this.client.getDataState('/fragments/', { params, responseMap: 'fragments', authorizationRequired: true });
    }
    bulkReadFragments2(params) {
        return this.client.get('/fragments/', { params, responseMap: 'fragments', authorizationRequired: true });
    }
    /**
     * List Published Remote Fragments
     * -------------
     *
     * List Published Remote Fragments
     */
    bulkReadPublishedFragments(params) {
        return this.client.getDataState('/fragments/published/', { params, responseMap: 'fragments', authorizationRequired: false });
    }
    bulkReadPublishedFragments2(params) {
        return this.client.get('/fragments/published/', { params, responseMap: 'fragments', authorizationRequired: false });
    }
    /**
     * Create Remote Fragment
     * -------------
     *
     * Create Remote Fragment
     */
    createFragment() {
        return this.client
            .post('/fragments/', {}, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
    /**
     * Delete Remote Fragment
     * -------------
     *
     * Delete Remote Fragment
     */
    deleteFragment(fragmentId) {
        return this.client
            .delete(`/fragments/${fragmentId}`, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
    /**
     * Merge Remote Fragment
     * -------------
     *
     * Merge Remote Fragment
     */
    mergeFragment(fragmentId) {
        return this.client
            .post(`/fragments/${fragmentId}/merge/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
    /**
     * Publish Remote Fragment
     * -------------
     *
     * Publish Remote Fragment
     */
    publishFragment(fragmentId) {
        return this.client
            .put(`/fragments/${fragmentId}/publish/`, {}, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
    /**
     * Read Remote Fragment
     * -------------
     *
     * Read Remote Fragment
     */
    readFragment(fragmentId) {
        return this.client.getDataState(`/fragments/${fragmentId}`, { authorizationRequired: true });
    }
    readFragment2(fragmentId) {
        return this.client.get(`/fragments/${fragmentId}`, { authorizationRequired: true });
    }
    /**
     * Read Fragment Diff
     * -------------
     *
     * Read Fragment Diff
     */
    readFragmentDiff(fragmentId) {
        return this.client.getDataState(`/fragments/${fragmentId}/diff/`, { authorizationRequired: true });
    }
    readFragmentDiff2(fragmentId) {
        return this.client.get(`/fragments/${fragmentId}/diff/`, { authorizationRequired: true });
    }
    /**
     * Read Fragment Sample
     * -------------
     *
     * Read Fragment Sample
     */
    readFragmentSample(fragmentId) {
        return this.client.getDataState(`/fragments/${fragmentId}/sample/`, { authorizationRequired: false });
    }
    readFragmentSample2(fragmentId) {
        return this.client.get(`/fragments/${fragmentId}/sample/`, { authorizationRequired: false });
    }
    /**
     * Update Remote Fragment
     * -------------
     *
     * Update Remote Fragment
     */
    updateFragment(fragmentId, body) {
        return this.client
            .put(`/fragments/${fragmentId}`, body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
}
FragmentsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
FragmentsDomain.ctorParameters = () => [
    { type: ClientService }
];

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZnJhZ21lbnRzLmRvbWFpbi5qcyIsInNvdXJjZVJvb3QiOiJuZzovL0Bjb3NwaGVyZS9jbGllbnQvIiwic291cmNlcyI6WyJkb21haW5zL2ZyYWdtZW50cy9mcmFnbWVudHMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBTTlELE1BQU07SUFDRixZQUFvQixNQUFxQjtRQUFyQixXQUFNLEdBQU4sTUFBTSxDQUFlO0lBQUcsQ0FBQztJQUU3Qzs7Ozs7T0FLRztJQUNJLGlCQUFpQixDQUFDLE1BQWdDO1FBQ3JELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBc0MsYUFBYSxFQUFFLEVBQUUsTUFBTSxFQUFFLFdBQVcsRUFBRSxXQUFXLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUMzSixDQUFDO0lBRU0sa0JBQWtCLENBQUMsTUFBZ0M7UUFDdEQsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFzQyxhQUFhLEVBQUUsRUFBRSxNQUFNLEVBQUUsV0FBVyxFQUFFLFdBQVcsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ2xKLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNJLDBCQUEwQixDQUFDLE1BQXlDO1FBQ3ZFLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBK0MsdUJBQXVCLEVBQUUsRUFBRSxNQUFNLEVBQUUsV0FBVyxFQUFFLFdBQVcsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQyxDQUFDO0lB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QUFVLFVBQVUsRUFBRSxFQUFFLHFCQUFxQixFQUFFLEtBQUssRUFBRSxDQUFDLENBQUM7SUFDeEksQ0FBQztJQUVNLG1CQUFtQixDQUFDLFVBQWU7UUFDdEMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUErQixjQUFjLFVBQVUsVUFBVSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUMsQ0FBQztJQUMvSCxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSSxjQUFjLENBQUMsVUFBZSxFQUFFLElBQTBCO1FBQzdELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLEdBQUcsQ0FBMkIsY0FBYyxVQUFVLEVBQUUsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUNoRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMxQyxDQUFDOzs7WUFwSUosVUFBVTs7OztZQUxGLGFBQWEiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIEZyYWdtZW50cyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9mcmFnbWVudHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZyYWdtZW50c0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZnJhZ21lbnRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRGcmFnbWVudHMyKHBhcmFtczogWC5CdWxrUmVhZEZyYWdtZW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPignL2ZyYWdtZW50cy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdmcmFnbWVudHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBQdWJsaXNoZWQgUmVtb3RlIEZyYWdtZW50c1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgUHVibGlzaGVkIFJlbW90ZSBGcmFnbWVudHNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHMocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUmVzcG9uc2VFbnRpdHlbXT4oJy9mcmFnbWVudHMvcHVibGlzaGVkLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2ZyYWdtZW50cycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50czIocGFyYW1zOiBYLkJ1bGtSZWFkUHVibGlzaGVkRnJhZ21lbnRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRQdWJsaXNoZWRGcmFnbWVudHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFB1Ymxpc2hlZEZyYWdtZW50c1Jlc3BvbnNlRW50aXR5W10+KCcvZnJhZ21lbnRzL3B1Ymxpc2hlZC8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdmcmFnbWVudHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBDcmVhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZyYWdtZW50KCk6IE9ic2VydmFibGU8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVGcmFnbWVudFJlc3BvbnNlPignL2ZyYWdtZW50cy8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZWxldGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRGVsZXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBNZXJnZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBNZXJnZSBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKi9cbiAgICBwdWJsaWMgbWVyZ2VGcmFnbWVudChmcmFnbWVudElkOiBhbnkpOiBPYnNlcnZhYmxlPFguTWVyZ2VGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5NZXJnZUZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vbWVyZ2UvYCwge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUHVibGlzaCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBQdWJsaXNoIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyBwdWJsaXNoRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlB1Ymxpc2hGcmFnbWVudFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlB1Ymxpc2hGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L3B1Ymxpc2gvYCwge30sIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBSZW1vdGUgRnJhZ21lbnRcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRnJhZ21lbnQoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRnJhZ21lbnQyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50UmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBSZWFkIEZyYWdtZW50IERpZmZcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIEZyYWdtZW50IERpZmZcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50RGlmZihmcmFnbWVudElkOiBhbnkpOiBEYXRhU3RhdGU8WC5SZWFkRnJhZ21lbnREaWZmUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfS9kaWZmL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEZyYWdtZW50RGlmZjIoZnJhZ21lbnRJZDogYW55KTogT2JzZXJ2YWJsZTxYLlJlYWRGcmFnbWVudERpZmZSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50RGlmZlJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L2RpZmYvYCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVhZCBGcmFnbWVudCBTYW1wbGVcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBSZWFkIEZyYWdtZW50IFNhbXBsZVxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkRnJhZ21lbnRTYW1wbGUoZnJhZ21lbnRJZDogYW55KTogRGF0YVN0YXRlPFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGcmFnbWVudFNhbXBsZVJlc3BvbnNlPihgL2ZyYWdtZW50cy8ke2ZyYWdtZW50SWR9L3NhbXBsZS9gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRnJhZ21lbnRTYW1wbGUyKGZyYWdtZW50SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkRnJhZ21lbnRTYW1wbGVSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguUmVhZEZyYWdtZW50U2FtcGxlUmVzcG9uc2U+KGAvZnJhZ21lbnRzLyR7ZnJhZ21lbnRJZH0vc2FtcGxlL2AsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBVcGRhdGUgUmVtb3RlIEZyYWdtZW50XG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogVXBkYXRlIFJlbW90ZSBGcmFnbWVudFxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVGcmFnbWVudChmcmFnbWVudElkOiBhbnksIGJvZHk6IFguVXBkYXRlRnJhZ21lbnRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUZyYWdtZW50UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlRnJhZ21lbnRSZXNwb25zZT4oYC9mcmFnbWVudHMvJHtmcmFnbWVudElkfWAsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG59Il19