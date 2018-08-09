/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Tasks Management Domain
 */
import { Injectable } from '@angular/core';
import { ClientService } from '../../services/client.service';
var TasksDomain = /** @class */ (function () {
    function TasksDomain(client) {
        this.client = client;
    }
    /**
     * List Tasks
     * -------------
     *
     * List tasks
     */
    TasksDomain.prototype.bulkReadTasks = function (params) {
        return this.client.getDataState('/tasks/', { params: params, responseMap: 'data', authorizationRequired: true });
    };
    TasksDomain.prototype.bulkReadTasks2 = function (params) {
        return this.client.get('/tasks/', { params: params, responseMap: 'data', authorizationRequired: true });
    };
    /**
     * List Task Bins
     * -------------
     *
     * List Tasks Bins
     */
    TasksDomain.prototype.bulkReadTaskBins = function (params) {
        return this.client.getDataState('/tasks/bins/', { params: params, responseMap: 'data', authorizationRequired: true });
    };
    TasksDomain.prototype.bulkReadTaskBins2 = function (params) {
        return this.client.get('/tasks/bins/', { params: params, responseMap: 'data', authorizationRequired: true });
    };
    TasksDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    TasksDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return TasksDomain;
}());
export { TasksDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGFza3MuZG9tYWluLmpzIiwic291cmNlUm9vdCI6Im5nOi8vQGNvc3BoZXJlL2NsaWVudC8iLCJzb3VyY2VzIjpbImRvbWFpbnMvdGFza3MvdGFza3MuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUszQyxPQUFPLEVBQUUsYUFBYSxFQUFFLE1BQU0sK0JBQStCLENBQUM7QUFLOUQ7SUFFSSxxQkFBb0IsTUFBcUI7UUFBckIsV0FBTSxHQUFOLE1BQU0sQ0FBZTtJQUFHLENBQUM7SUFFN0M7Ozs7O09BS0c7SUFDSSxtQ0FBYSxHQUFwQixVQUFxQixNQUE0QjtRQUM3QyxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQWtDLFNBQVMsRUFBRSxFQUFFLE1BQU0sUUFBQSxFQUFFLFdBQVcsRUFBRSxNQUFNLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUM5SSxDQUFDO0lBRU0sb0NBQWMsR0FBckIsVUFBc0IsTUFBNEI7UUFDOUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFrQyxTQUFTLEVBQUUsRUFBRSxNQUFNLFFBQUEsRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDckksQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0ksc0NBQWdCLEdBQXZCLFVBQXdCLE1BQStCO1FBQ25ELE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBcUMsY0FBYyxFQUFFLEVBQUUsTUFBTSxRQUFBLEVBQUUsV0FBVyxFQUFFLE1BQU0sRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ3RKLENBQUM7SUFFTSx1Q0FBaUIsR0FBeEIsVUFBeUIsTUFBK0I7UUFDcEQsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFxQyxjQUFjLEVBQUUsRUFBRSxNQUFNLFFBQUEsRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDN0ksQ0FBQzs7Z0JBOUJKLFVBQVU7Ozs7Z0JBTEYsYUFBYTs7SUFxQ3RCLGtCQUFDO0NBQUEsQUFoQ0QsSUFnQ0M7U0EvQlksV0FBVyIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICAqIFRISVMgRklMRSBXQVMgQVVUT0dFTkVSQVRFRCwgQUxMIE1BTlVBTCBDSEFOR0VTIENBTiBCRVxuICAqIE9WRVJXUklUVEVOXG4gICovXG5cbi8qKlxuICogVGFza3MgTWFuYWdlbWVudCBEb21haW5cbiAqL1xuaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuaW1wb3J0IHsgZmlsdGVyIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0ICogYXMgXyBmcm9tICd1bmRlcnNjb3JlJztcblxuaW1wb3J0IHsgQ2xpZW50U2VydmljZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IERhdGFTdGF0ZSB9IGZyb20gJy4uLy4uL3NlcnZpY2VzL2NsaWVudC5pbnRlcmZhY2UnO1xuXG5pbXBvcnQgKiBhcyBYIGZyb20gJy4vdGFza3MubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFRhc2tzRG9tYWluIHtcbiAgICBjb25zdHJ1Y3Rvcihwcml2YXRlIGNsaWVudDogQ2xpZW50U2VydmljZSkge31cblxuICAgIC8qKlxuICAgICAqIExpc3QgVGFza3NcbiAgICAgKiAtLS0tLS0tLS0tLS0tXG4gICAgICpcbiAgICAgKiBMaXN0IHRhc2tzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkVGFza3MocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkVGFza3NSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4oJy90YXNrcy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza3NRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tzUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRUYXNrc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvJywgeyBwYXJhbXMsIHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBMaXN0IFRhc2sgQmluc1xuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIExpc3QgVGFza3MgQmluc1xuICAgICAqL1xuICAgIHB1YmxpYyBidWxrUmVhZFRhc2tCaW5zKHBhcmFtczogWC5CdWxrUmVhZFRhc2tCaW5zUXVlcnkpOiBEYXRhU3RhdGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0RGF0YVN0YXRlPFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvYmlucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cbiAgICBcbiAgICBwdWJsaWMgYnVsa1JlYWRUYXNrQmluczIocGFyYW1zOiBYLkJ1bGtSZWFkVGFza0JpbnNRdWVyeSk6IE9ic2VydmFibGU8WC5CdWxrUmVhZFRhc2tCaW5zUmVzcG9uc2VFbnRpdHlbXT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnQuZ2V0PFguQnVsa1JlYWRUYXNrQmluc1Jlc3BvbnNlRW50aXR5W10+KCcvdGFza3MvYmlucy8nLCB7IHBhcmFtcywgcmVzcG9uc2VNYXA6ICdkYXRhJywgYXV0aG9yaXphdGlvblJlcXVpcmVkOiB0cnVlIH0pO1xuICAgIH1cblxufSJdfQ==