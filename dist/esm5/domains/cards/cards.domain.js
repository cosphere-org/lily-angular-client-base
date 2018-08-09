/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Cards Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
var CardsDomain = /** @class */ (function () {
    function CardsDomain(client) {
        this.client = client;
    }
    /**
     * Remove Card
     * -------------
     *
     * Remove list of Cards specified by their ids.
     */
    CardsDomain.prototype.bulkDeleteCards = function (params) {
        return this.client
            .delete('/cards/', { params: params, authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Bulk Read Multiple Cards
     * -------------
     *
     * List subset of Cards depending on various filtering flags.
     */
    CardsDomain.prototype.bulkReadCards = function (params) {
        return this.client.getDataState('/cards/', { params: params, responseMap: 'cards', authorizationRequired: true });
    };
    CardsDomain.prototype.bulkReadCards2 = function (params) {
        return this.client.get('/cards/', { params: params, responseMap: 'cards', authorizationRequired: true });
    };
    CardsDomain.prototype.bulkReadGeometriesOnly2 = function (params) {
        return this.client.get('/cards/', { params: params, responseMap: 'cards', authorizationRequired: true });
    };
    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    CardsDomain.prototype.createCard = function (body) {
        return this.client
            .post('/cards/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Read Card by Id
     * -------------
     *
     * Read Card by `id`.
     */
    CardsDomain.prototype.readCard = function (cardId) {
        return this.client.getDataState("/cards/" + cardId, { authorizationRequired: true });
    };
    CardsDomain.prototype.readCard2 = function (cardId, params) {
        return this.client.get("/cards/" + cardId, { params: params, authorizationRequired: true });
    };
    /**
     * Creating a single Card
     * -------------
     *
     * Enables one to create a single Card instance.
     */
    CardsDomain.prototype.updateCard = function (cardId, body) {
        return this.client
            .put("/cards/" + cardId, body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    CardsDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    CardsDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return CardsDomain;
}());
export { CardsDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2FyZHMuZG9tYWluLmpzIiwic291cmNlUm9vdCI6Im5nOi8vQGNvc3BoZXJlL2NsaWVudC8iLCJzb3VyY2VzIjpbImRvbWFpbnMvY2FyZHMvY2FyZHMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBSzlEO0lBRUkscUJBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7SUFBRyxDQUFDO0lBRTdDOzs7OztPQUtHO0lBQ0kscUNBQWUsR0FBdEIsVUFBdUIsTUFBOEI7UUFDakQsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsTUFBTSxDQUE0QixTQUFTLEVBQUUsRUFBRSxNQUFNLFFBQUEsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUNyRixJQUFJLENBQUMsTUFBTSxDQUFDLFVBQUEsQ0FBQyxJQUFJLE9BQUEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFiLENBQWEsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0ksbUNBQWEsR0FBcEIsVUFBcUIsTUFBNEI7UUFDN0MsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFrQyxTQUFTLEVBQUUsRUFBRSxNQUFNLFFBQUEsRUFBRSxXQUFXLEVBQUUsT0FBTyxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDL0ksQ0FBQztJQUVNLG9DQUFjLEdBQXJCLFVBQXNCLE1BQTRCO1FBQzlDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBa0MsU0FBUyxFQUFFLEVBQUUsTUFBTSxRQUFBLEVBQUUsV0FBVyxFQUFFLE9BQU8sRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ3RJLENBQUM7SUFFTSw2Q0FBdUIsR0FBOUIsVUFBK0IsTUFBNEI7UUFDdkQsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFrQyxTQUFTLEVBQUUsRUFBRSxNQUFNLFFBQUEsRUFBRSxXQUFXLEVBQUUsT0FBTyxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDdEksQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0ksZ0NBQVUsR0FBakIsVUFBa0IsSUFBc0I7UUFDcEMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUF1QixTQUFTLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDNUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNJLDhCQUFRLEdBQWYsVUFBZ0IsTUFBVztRQUN2QixNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQXFCLFlBQVUsTUFBUSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUM3RyxDQUFDO0lBRU0sK0JBQVMsR0FBaEIsVUFBaUIsTUFBVyxFQUFFLE1BQVk7UUFDdEMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFxQixZQUFVLE1BQVEsRUFBRSxFQUFFLE1BQU0sUUFBQSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDNUcsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0ksZ0NBQVUsR0FBakIsVUFBa0IsTUFBVyxFQUFFLElBQXNCO1FBQ2pELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLEdBQUcsQ0FBdUIsWUFBVSxNQUFRLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDcEYsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7O2dCQXRFSixVQUFVOzs7O2dCQUxGLGFBQWE7O0lBNkV0QixrQkFBQztDQUFBLEFBeEVELElBd0VDO1NBdkVZLFdBQVciLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAgKiBUSElTIEZJTEUgV0FTIEFVVE9HRU5FUkFURUQsIEFMTCBNQU5VQUwgQ0hBTkdFUyBDQU4gQkVcbiAgKiBPVkVSV1JJVFRFTlxuICAqL1xuXG4vKipcbiAqIENhcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2NhcmRzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDYXJkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBSZW1vdmUgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlbW92ZSBsaXN0IG9mIENhcmRzIHNwZWNpZmllZCBieSB0aGVpciBpZHMuXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtEZWxldGVDYXJkcyhwYXJhbXM6IFguQnVsa0RlbGV0ZUNhcmRzUXVlcnkpOiBPYnNlcnZhYmxlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAuZGVsZXRlPFguQnVsa0RlbGV0ZUNhcmRzUmVzcG9uc2U+KCcvY2FyZHMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIEJ1bGsgUmVhZCBNdWx0aXBsZSBDYXJkc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3Qgc3Vic2V0IG9mIENhcmRzIGRlcGVuZGluZyBvbiB2YXJpb3VzIGZpbHRlcmluZyBmbGFncy5cbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRDYXJkcyhwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogRGF0YVN0YXRlPFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPignL2NhcmRzLycsIHsgcGFyYW1zLCByZXNwb25zZU1hcDogJ2NhcmRzJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRDYXJkczIocGFyYW1zOiBYLkJ1bGtSZWFkQ2FyZHNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRDYXJkc1Jlc3BvbnNlRW50aXR5W10+KCcvY2FyZHMvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnY2FyZHMnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZEdlb21ldHJpZXNPbmx5MihwYXJhbXM6IFguQnVsa1JlYWRDYXJkc1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkQ2FyZHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZENhcmRzUmVzcG9uc2VFbnRpdHlbXT4oJy9jYXJkcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdjYXJkcycsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGluZyBhIHNpbmdsZSBDYXJkXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogRW5hYmxlcyBvbmUgdG8gY3JlYXRlIGEgc2luZ2xlIENhcmQgaW5zdGFuY2UuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUNhcmQoYm9keTogWC5DcmVhdGVDYXJkQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUNhcmRSZXNwb25zZT4oJy9jYXJkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgQ2FyZCBieSBJZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFJlYWQgQ2FyZCBieSBgaWRgLlxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkQ2FyZChjYXJkSWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRDYXJkUmVzcG9uc2U+KGAvY2FyZHMvJHtjYXJkSWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkQ2FyZDIoY2FyZElkOiBhbnksIHBhcmFtcz86IGFueSk6IE9ic2VydmFibGU8WC5SZWFkQ2FyZFJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkQ2FyZFJlc3BvbnNlPihgL2NhcmRzLyR7Y2FyZElkfWAsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRpbmcgYSBzaW5nbGUgQ2FyZFxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIEVuYWJsZXMgb25lIHRvIGNyZWF0ZSBhIHNpbmdsZSBDYXJkIGluc3RhbmNlLlxuICAgICAqL1xuICAgIHB1YmxpYyB1cGRhdGVDYXJkKGNhcmRJZDogYW55LCBib2R5OiBYLlVwZGF0ZUNhcmRCb2R5KTogT2JzZXJ2YWJsZTxYLlVwZGF0ZUNhcmRSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wdXQ8WC5VcGRhdGVDYXJkUmVzcG9uc2U+KGAvY2FyZHMvJHtjYXJkSWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iXX0=