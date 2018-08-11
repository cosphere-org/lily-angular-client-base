/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Processes Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
var ProcessesDomain = /** @class */ (function () {
    function ProcessesDomain(client) {
        this.client = client;
    }
    /**
     * Create Deletion Process
     */
    ProcessesDomain.prototype.createDeletionProcess = function (body) {
        return this.client
            .post('/mediafiles/processes/deletions/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Download Process
     */
    ProcessesDomain.prototype.createDownloadProcess = function (body) {
        return this.client
            .post('/mediafiles/processes/downloads/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Media Lock
     */
    ProcessesDomain.prototype.createMediaLock = function (body) {
        return this.client
            .post('/mediafiles/locks/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Upload Process
     */
    ProcessesDomain.prototype.createUploadProcess = function (body) {
        return this.client
            .post('/mediafiles/processes/uploads/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Read invariants for a given uri
     */
    ProcessesDomain.prototype.readInvariants = function (params) {
        return this.client.getDataState('/mediafiles/invariants/', { params: params, authorizationRequired: true });
    };
    ProcessesDomain.prototype.readInvariants2 = function (params) {
        return this.client.get('/mediafiles/invariants/', { params: params, authorizationRequired: true });
    };
    /**
     * Create Media Lock
     */
    ProcessesDomain.prototype.readProcessState = function (params) {
        return this.client.getDataState('/mediafiles/processes/', { params: params, authorizationRequired: true });
    };
    ProcessesDomain.prototype.readProcessState2 = function (params) {
        return this.client.get('/mediafiles/processes/', { params: params, authorizationRequired: true });
    };
    /**
     * Sign Process dedicated to upload and conversion of media file
     */
    ProcessesDomain.prototype.signProcess = function (params) {
        return this.client.getDataState('/mediafiles/processes/sign/', { params: params, authorizationRequired: true });
    };
    ProcessesDomain.prototype.signProcess2 = function (params) {
        return this.client.get('/mediafiles/processes/sign/', { params: params, authorizationRequired: true });
    };
    /**
     * Watch conversion status
     * -------------
     *
     * Endpoint called by the external conversion service.
     */
    ProcessesDomain.prototype.watchConversionStatus = function (waiterId, params) {
        return this.client.getDataState("/mediafiles/convert_processes/(?P<process_id>[0-9a-zA-Z_-=]+)/" + waiterId, { params: params, authorizationRequired: false });
    };
    ProcessesDomain.prototype.watchConversionStatus2 = function (waiterId, params) {
        return this.client.get("/mediafiles/convert_processes/(?P<process_id>[0-9a-zA-Z_-=]+)/" + waiterId, { params: params, authorizationRequired: false });
    };
    ProcessesDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    ProcessesDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return ProcessesDomain;
}());
export { ProcessesDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicHJvY2Vzc2VzLmRvbWFpbi5qcyIsInNvdXJjZVJvb3QiOiJuZzovL0Bjb3NwaGVyZS9jbGllbnQvIiwic291cmNlcyI6WyJkb21haW5zL3Byb2Nlc3Nlcy9wcm9jZXNzZXMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBSzlEO0lBRUkseUJBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7SUFBRyxDQUFDO0lBRTdDOztPQUVHO0lBQ0ksK0NBQXFCLEdBQTVCLFVBQTZCLElBQWlDO1FBQzFELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBa0Msa0NBQWtDLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDaEgsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7SUFFRDs7T0FFRztJQUNJLCtDQUFxQixHQUE1QixVQUE2QixJQUFpQztRQUMxRCxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQWtDLGtDQUFrQyxFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDO2FBQ2hILElBQUksQ0FBQyxNQUFNLENBQUMsVUFBQSxDQUFDLElBQUksT0FBQSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLEVBQWIsQ0FBYSxDQUFDLENB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QUFFLENBQUMsQ0FBQztJQUN0TCxDQUFDOztnQkFyRkosVUFBVTs7OztnQkFMRixhQUFhOztJQTRGdEIsc0JBQUM7Q0FBQSxBQXZGRCxJQXVGQztTQXRGWSxlQUFlIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBQcm9jZXNzZXMgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vcHJvY2Vzc2VzLm1vZGVscyc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBQcm9jZXNzZXNEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIERlbGV0aW9uIFByb2Nlc3NcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRGVsZXRpb25Qcm9jZXNzKGJvZHk6IFguQ3JlYXRlRGVsZXRpb25Qcm9jZXNzQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEZWxldGlvblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRGVsZXRpb25Qcm9jZXNzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvZGVsZXRpb25zLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIERvd25sb2FkIFByb2Nlc3NcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRG93bmxvYWRQcm9jZXNzKGJvZHk6IFguQ3JlYXRlRG93bmxvYWRQcm9jZXNzQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVEb3dubG9hZFByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRG93bmxvYWRQcm9jZXNzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvZG93bmxvYWRzLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1lZGlhIExvY2tcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlTWVkaWFMb2NrKGJvZHk6IFguQ3JlYXRlTWVkaWFMb2NrQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVNZWRpYUxvY2tSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlTWVkaWFMb2NrUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9sb2Nrcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBVcGxvYWQgUHJvY2Vzc1xuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVVcGxvYWRQcm9jZXNzKGJvZHk6IFguQ3JlYXRlVXBsb2FkUHJvY2Vzc0JvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlVXBsb2FkUHJvY2Vzc1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVVcGxvYWRQcm9jZXNzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvdXBsb2Fkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgaW52YXJpYW50cyBmb3IgYSBnaXZlbiB1cmlcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEludmFyaWFudHMocGFyYW1zOiBYLlJlYWRJbnZhcmlhbnRzUXVlcnkpOiBEYXRhU3RhdGU8WC5SZWFkSW52YXJpYW50c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkSW52YXJpYW50c1Jlc3BvbnNlPignL21lZGlhZmlsZXMvaW52YXJpYW50cy8nLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgcmVhZEludmFyaWFudHMyKHBhcmFtczogWC5SZWFkSW52YXJpYW50c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLlJlYWRJbnZhcmlhbnRzUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLlJlYWRJbnZhcmlhbnRzUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9pbnZhcmlhbnRzLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1lZGlhIExvY2tcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZFByb2Nlc3NTdGF0ZShwYXJhbXM6IFguUmVhZFByb2Nlc3NTdGF0ZVF1ZXJ5KTogRGF0YVN0YXRlPFguUmVhZFByb2Nlc3NTdGF0ZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRQcm9jZXNzU3RhdGUyKHBhcmFtczogWC5SZWFkUHJvY2Vzc1N0YXRlUXVlcnkpOiBPYnNlcnZhYmxlPFguUmVhZFByb2Nlc3NTdGF0ZVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkUHJvY2Vzc1N0YXRlUmVzcG9uc2U+KCcvbWVkaWFmaWxlcy9wcm9jZXNzZXMvJywgeyBwYXJhbXMsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBTaWduIFByb2Nlc3MgZGVkaWNhdGVkIHRvIHVwbG9hZCBhbmQgY29udmVyc2lvbiBvZiBtZWRpYSBmaWxlXG4gICAgICovXG4gICAgcHVibGljIHNpZ25Qcm9jZXNzKHBhcmFtczogWC5TaWduUHJvY2Vzc1F1ZXJ5KTogRGF0YVN0YXRlPFguU2lnblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguU2lnblByb2Nlc3NSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy9zaWduLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBzaWduUHJvY2VzczIocGFyYW1zOiBYLlNpZ25Qcm9jZXNzUXVlcnkpOiBPYnNlcnZhYmxlPFguU2lnblByb2Nlc3NSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguU2lnblByb2Nlc3NSZXNwb25zZT4oJy9tZWRpYWZpbGVzL3Byb2Nlc3Nlcy9zaWduLycsIHsgcGFyYW1zLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogV2F0Y2ggY29udmVyc2lvbiBzdGF0dXNcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBFbmRwb2ludCBjYWxsZWQgYnkgdGhlIGV4dGVybmFsIGNvbnZlcnNpb24gc2VydmljZS5cbiAgICAgKi9cbiAgICBwdWJsaWMgd2F0Y2hDb252ZXJzaW9uU3RhdHVzKHdhaXRlcklkOiBhbnksIHBhcmFtczogWC5XYXRjaENvbnZlcnNpb25TdGF0dXNRdWVyeSk6IERhdGFTdGF0ZTxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5XYXRjaENvbnZlcnNpb25TdGF0dXNSZXNwb25zZT4oYC9tZWRpYWZpbGVzL2NvbnZlcnRfcHJvY2Vzc2VzLyg/UDxwcm9jZXNzX2lkPlswLTlhLXpBLVpcXF9cXC1cXD1dKykvJHt3YWl0ZXJJZH1gLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHdhdGNoQ29udmVyc2lvblN0YXR1czIod2FpdGVySWQ6IGFueSwgcGFyYW1zOiBYLldhdGNoQ29udmVyc2lvblN0YXR1c1F1ZXJ5KTogT2JzZXJ2YWJsZTxYLldhdGNoQ29udmVyc2lvblN0YXR1c1Jlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5XYXRjaENvbnZlcnNpb25TdGF0dXNSZXNwb25zZT4oYC9tZWRpYWZpbGVzL2NvbnZlcnRfcHJvY2Vzc2VzLyg/UDxwcm9jZXNzX2lkPlswLTlhLXpBLVpcXF9cXC1cXD1dKykvJHt3YWl0ZXJJZH1gLCB7IHBhcmFtcywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KTtcbiAgICB9XG5cbn0iXX0=