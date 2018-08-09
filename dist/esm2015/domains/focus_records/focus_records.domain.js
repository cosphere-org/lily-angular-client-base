/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Focus Records Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
export class FocusRecordsDomain {
    constructor(client) {
        this.client = client;
    }
    /**
     * Create Focus Record
     */
    createFocusrecord(body) {
        return this.client
            .post('/focus_records/', body, { authorizationRequired: true })
            .pipe(filter(x => !_.isEmpty(x)));
    }
    /**
     * Read Focus Record Summary
     */
    readFocusRecordSummary() {
        return this.client.getDataState('/focus_records/summary/', { authorizationRequired: true });
    }
    readFocusRecordSummary2() {
        return this.client.get('/focus_records/summary/', { authorizationRequired: true });
    }
}
FocusRecordsDomain.decorators = [
    { type: Injectable }
];
/** @nocollapse */
FocusRecordsDomain.ctorParameters = () => [
    { type: ClientService }
];

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZm9jdXNfcmVjb3Jkcy5kb21haW4uanMiLCJzb3VyY2VSb290Ijoibmc6Ly9AY29zcGhlcmUvY2xpZW50LyIsInNvdXJjZXMiOlsiZG9tYWlucy9mb2N1c19yZWNvcmRzL2ZvY3VzX3JlY29yZHMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBTTlELE1BQU07SUFDRixZQUFvQixNQUFxQjtRQUFyQixXQUFNLEdBQU4sTUFBTSxDQUFlO0lBQUcsQ0FBQztJQUU3Qzs7T0FFRztJQUNJLGlCQUFpQixDQUFDLElBQTZCO1FBQ2xELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBOEIsaUJBQWlCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDM0YsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVEOztPQUVHO0lBQ0ksc0JBQXNCO1FBQ3pCLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBbUMseUJBQXlCLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ2xJLENBQUM7SUFFTSx1QkFBdUI7UUFDMUIsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFtQyx5QkFBeUIsRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDekgsQ0FBQzs7O1lBdEJKLFVBQVU7Ozs7WUFMRixhQUFhIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBGb2N1cyBSZWNvcmRzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL2ZvY3VzX3JlY29yZHMubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEZvY3VzUmVjb3Jkc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgRm9jdXMgUmVjb3JkXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZvY3VzcmVjb3JkKGJvZHk6IFguQ3JlYXRlRm9jdXNyZWNvcmRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZvY3VzcmVjb3JkUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZvY3VzcmVjb3JkUmVzcG9uc2U+KCcvZm9jdXNfcmVjb3Jkcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgRm9jdXMgUmVjb3JkIFN1bW1hcnlcbiAgICAgKi9cbiAgICBwdWJsaWMgcmVhZEZvY3VzUmVjb3JkU3VtbWFyeSgpOiBEYXRhU3RhdGU8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRGb2N1c1JlY29yZFN1bW1hcnlSZXNwb25zZT4oJy9mb2N1c19yZWNvcmRzL3N1bW1hcnkvJywgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyByZWFkRm9jdXNSZWNvcmRTdW1tYXJ5MigpOiBPYnNlcnZhYmxlPFguUmVhZEZvY3VzUmVjb3JkU3VtbWFyeVJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkRm9jdXNSZWNvcmRTdW1tYXJ5UmVzcG9uc2U+KCcvZm9jdXNfcmVjb3Jkcy9zdW1tYXJ5LycsIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSJdfQ==