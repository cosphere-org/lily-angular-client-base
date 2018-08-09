/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Hashtags Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
var HashtagsDomain = /** @class */ (function () {
    function HashtagsDomain(client) {
        this.client = client;
    }
    /**
     * List Hashtags
     * -------------
     *
     * Enables one to list a series of Hashtag instances. It accepts various query parameters such as: - `limit` - `offset` - `first_character`
     */
    HashtagsDomain.prototype.bulkReadHashtags = function (params) {
        return this.client.getDataState('/hashtags/', { params: params, responseMap: 'hashtags', authorizationRequired: true });
    };
    HashtagsDomain.prototype.bulkReadHashtags2 = function (params) {
        return this.client.get('/hashtags/', { params: params, responseMap: 'hashtags', authorizationRequired: true });
    };
    /**
     * Creating a single Hashtag
     * -------------
     *
     * Enables one to create a single Hashtag instance.
     */
    HashtagsDomain.prototype.createHashtag = function (body) {
        return this.client
            .post('/hashtags/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Removing a single Hashtag
     * -------------
     *
     * Enables one to detach a single Hashtag instance from a list cards given by `card_ids`.
     */
    HashtagsDomain.prototype.deleteHashtag = function (hashtagId, params) {
        return this.client
            .delete("/hashtags/" + hashtagId, { params: params, authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * List Hashtags TOC
     * -------------
     *
     * Enables one to list Hashtags Table of Contents made out of Hashtags. Note: Currently this endpoint returns only a flat list of hashtags with the count of Cards with which they're attached to. In the future though one could propose a mechanism which could calculate hierarchy between those hashtags (parent - child relationships) and ordering based on the knowledge grid topology. It accepts various query parameters such as: - `limit` - `offset`
     */
    HashtagsDomain.prototype.readHashtagsToc = function (params) {
        return this.client.getDataState('/hashtags/toc', { params: params, authorizationRequired: true });
    };
    HashtagsDomain.prototype.readHashtagsToc2 = function (params) {
        return this.client.get('/hashtags/toc', { params: params, authorizationRequired: true });
    };
    /**
     * Updating a single Hashtag
     * -------------
     *
     * Enables one to update a single Hashtag instance with a list of `card_ids` to which it should get attached to.
     */
    HashtagsDomain.prototype.updateHashtag = function (hashtagId, body) {
        return this.client
            .put("/hashtags/" + hashtagId, body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    HashtagsDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    HashtagsDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return HashtagsDomain;
}());
export { HashtagsDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaGFzaHRhZ3MuZG9tYWluLmpzIiwic291cmNlUm9vdCI6Im5nOi8vQGNvc3BoZXJlL2NsaWVudC8iLCJzb3VyY2VzIjpbImRvbWFpbnMvaGFzaHRhZ3MvaGFzaHRhZ3MuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBSzlEO0lBRUksd0JBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7SUFBRyxDQUFDO0lBRTdDOzs7OztPQUtHO0lBQ0kseUNBQWdCLEdBQXZCLFVBQXdCLE1BQStCO1FBQ25ELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBcUMsWUFBWSxFQUFFLEVBQUUsTUFBTSxRQUFBLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ3hKLENBQUM7SUFFTSwwQ0FBaUIsR0FBeEIsVUFBeUIsTUFBK0I7UUFDcEQsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFxQyxZQUFZLEVBQUUsRUFBRSxNQUFNLFFBQUEsRUFBRSxXQUFXLEVBQUUsVUFBVSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDL0ksQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0ksc0NBQWEsR0FBcEIsVUFBcUIsSUFBeUI7UUFDMUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUEwQixZQUFZLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDbEYsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNJLHNDQUFhLEdBQXBCLFVBQXFCLFNBQWMsRUFBRSxNQUE0QjtRQUM3RCxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU07YUFDYixNQUFNLENBQTBCLGVBQWEsU0FBVyxFQUFFLEVBQUUsTUFBTSxRQUFBLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDbEcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNJLHdDQUFlLEdBQXRCLFVBQXVCLE1BQThCO1FBQ2pELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBNEIsZUFBZSxFQUFFLEVBQUUsTUFBTSxRQUFBLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUN6SCxDQUFDO0lBRU0seUNBQWdCLEdBQXZCLFVBQXdCLE1BQThCO1FBQ2xELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBNEIsZUFBZSxFQUFFLEVBQUUsTUFBTSxRQUFBLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUNoSCxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSSxzQ0FBYSxHQUFwQixVQUFxQixTQUFjLEVBQUUsSUFBeUI7UUFDMUQsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsR0FBRyxDQUEwQixlQUFhLFNBQVcsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUM3RixJQUFJLENBQUMsTUFBTSxDQUFDLFVBQUEsQ0FBQyxJQUFJLE9BQUEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFiLENBQWEsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQzs7Z0JBbEVKLFVBQVU7Ozs7Z0JBTEYsYUFBYTs7SUF5RXRCLHFCQUFDO0NBQUEsQUFwRUQsSUFvRUM7U0FuRVksY0FBYyIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogSGFzaHRhZ3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vaGFzaHRhZ3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEhhc2h0YWdzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgSGFzaHRhZ3NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBsaXN0IGEgc2VyaWVzIG9mIEhhc2h0YWcgaW5zdGFuY2VzLiBJdCBhY2NlcHRzIHZhcmlvdXMgcXVlcnkgcGFyYW1ldGVycyBzdWNoIGFzOiAtIGBsaW1pdGAgLSBgb2Zmc2V0YCAtIGBmaXJzdF9jaGFyYWN0ZXJgXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkSGFzaHRhZ3MocGFyYW1zOiBYLkJ1bGtSZWFkSGFzaHRhZ3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZEhhc2h0YWdzUmVzcG9uc2VFbnRpdHlbXT4oJy9oYXNodGFncy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdoYXNodGFncycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkSGFzaHRhZ3MyKHBhcmFtczogWC5CdWxrUmVhZEhhc2h0YWdzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRIYXNodGFnc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkSGFzaHRhZ3NSZXNwb25zZUVudGl0eVtdPignL2hhc2h0YWdzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2hhc2h0YWdzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0aW5nIGEgc2luZ2xlIEhhc2h0YWdcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBjcmVhdGUgYSBzaW5nbGUgSGFzaHRhZyBpbnN0YW5jZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlSGFzaHRhZyhib2R5OiBYLkNyZWF0ZUhhc2h0YWdCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUhhc2h0YWdSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlSGFzaHRhZ1Jlc3BvbnNlPignL2hhc2h0YWdzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogUmVtb3ZpbmcgYSBzaW5nbGUgSGFzaHRhZ1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGRldGFjaCBhIHNpbmdsZSBIYXNodGFnIGluc3RhbmNlIGZyb20gYSBsaXN0IGNhcmRzIGdpdmVuIGJ5IGBjYXJkX2lkc2AuXG4gICAgICovXG4gICAgcHVibGljIGRlbGV0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIHBhcmFtczogWC5EZWxldGVIYXNodGFnUXVlcnkpOiBPYnNlcnZhYmxlPFguRGVsZXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLmRlbGV0ZTxYLkRlbGV0ZUhhc2h0YWdSZXNwb25zZT4oYC9oYXNodGFncy8ke2hhc2h0YWdJZH1gLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogTGlzdCBIYXNodGFncyBUT0NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byBsaXN0IEhhc2h0YWdzIFRhYmxlIG9mIENvbnRlbnRzIG1hZGUgb3V0IG9mIEhhc2h0YWdzLiBOb3RlOiBDdXJyZW50bHkgdGhpcyBlbmRwb2ludCByZXR1cm5zIG9ubHkgYSBmbGF0IGxpc3Qgb2YgaGFzaHRhZ3Mgd2l0aCB0aGUgY291bnQgb2YgQ2FyZHMgd2l0aCB3aGljaCB0aGV5J3JlIGF0dGFjaGVkIHRvLiBJbiB0aGUgZnV0dXJlIHRob3VnaCBvbmUgY291bGQgcHJvcG9zZSBhIG1lY2hhbmlzbSB3aGljaCBjb3VsZCBjYWxjdWxhdGUgaGllcmFyY2h5IGJldHdlZW4gdGhvc2UgaGFzaHRhZ3MgKHBhcmVudCAtIGNoaWxkIHJlbGF0aW9uc2hpcHMpIGFuZCBvcmRlcmluZyBiYXNlZCBvbiB0aGUga25vd2xlZGdlIGdyaWQgdG9wb2xvZ3kuIEl0IGFjY2VwdHMgdmFyaW91cyBxdWVyeSBwYXJhbWV0ZXJzIHN1Y2ggYXM6IC0gYGxpbWl0YCAtIGBvZmZzZXRgXG4gICAgICovXG4gICAgcHVibGljIHJlYWRIYXNodGFnc1RvYyhwYXJhbXM6IFguUmVhZEhhc2h0YWdzVG9jUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguUmVhZEhhc2h0YWdzVG9jUmVzcG9uc2U+KCcvaGFzaHRhZ3MvdG9jJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRIYXNodGFnc1RvYzIocGFyYW1zOiBYLlJlYWRIYXNodGFnc1RvY1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRIYXNodGFnc1RvY1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkSGFzaHRhZ3NUb2NSZXNwb25zZT4oJy9oYXNodGFncy90b2MnLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFVwZGF0aW5nIGEgc2luZ2xlIEhhc2h0YWdcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmFibGVzIG9uZSB0byB1cGRhdGUgYSBzaW5nbGUgSGFzaHRhZyBpbnN0YW5jZSB3aXRoIGEgbGlzdCBvZiBgY2FyZF9pZHNgIHRvIHdoaWNoIGl0IHNob3VsZCBnZXQgYXR0YWNoZWQgdG8uXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUhhc2h0YWcoaGFzaHRhZ0lkOiBhbnksIGJvZHk6IFguVXBkYXRlSGFzaHRhZ0JvZHkpOiBPYnNlcnZhYmxlPFguVXBkYXRlSGFzaHRhZ1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnB1dDxYLlVwZGF0ZUhhc2h0YWdSZXNwb25zZT4oYC9oYXNodGFncy8ke2hhc2h0YWdJZH1gLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxufSJdfQ==