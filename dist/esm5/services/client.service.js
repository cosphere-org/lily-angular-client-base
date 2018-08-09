import { Injectable, Inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, throwError } from 'rxjs';
import { catchError, retry, map } from 'rxjs/operators';
import * as _ from 'underscore';
import * as i0 from "@angular/core";
import * as i1 from "@angular/common/http";
var ClientService = /** @class */ (function () {
    function ClientService(config, http) {
        this.config = config;
        this.http = http;
        /**
         * State for all GET payloads
         */
        this.state = new Map();
        this.defaultAuthToken = 'auth_token';
        /**
         * Cache time - every GET request is taken only if the last one
         * was invoked not earlier then `cacheTime` mins ago.
         * Only successful responses are cached (2xx)
         */
        this.cacheTime = 1000 * 60 * 60; // 60 mins
        this.baseUrl = this.config.baseUrl;
        this.authToken =
            this.config.authToken || this.defaultAuthToken;
    }
    ClientService.prototype.get = function (endpoint, options) {
        var url = this.getUrl(endpoint);
        var httpOptions = this.getHttpOptions(options);
        return this.http
            .get(url, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    };
    ClientService.prototype.post = function (endpoint, body, options) {
        var url = this.getUrl(endpoint);
        var httpOptions = this.getHttpOptions(options);
        return this.http
            .post(url, body, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    };
    ClientService.prototype.put = function (endpoint, body, options) {
        var url = this.getUrl(endpoint);
        var httpOptions = this.getHttpOptions(options);
        return this.http
            .put(url, body, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    };
    ClientService.prototype.delete = function (endpoint, options) {
        var url = this.getUrl(endpoint);
        var httpOptions = this.getHttpOptions(options);
        return this.http
            .delete(url, httpOptions)
            .pipe(retry(3), catchError(this.handleError));
    };
    ClientService.prototype.getDataState = function (endpoint, options) {
        var key = options && options.params ? endpoint + "_" + JSON.stringify(options.params) : endpoint;
        this.initState(key, options);
        var cache = true;
        var params;
        if (_.has(options, 'cache')) {
            cache = options.cache;
        }
        if (_.has(options, 'params')) {
            params = options.params;
        }
        // Get the endpoint state
        var state = this.state.get(key);
        // Do not allow invoke the same GET request while one is pending
        if (state.requestState.pending /*&& !_.isEmpty(params)*/) {
            return state.dataState;
        }
        var currentTime = +new Date();
        if (currentTime - state.requestState.cachedAt > this.cacheTime ||
            // !_.isEmpty(params) ||
            !cache) {
            state.requestState.pending = true;
            this.get(endpoint, options)
                .pipe(map(function (data) { return (options.responseMap ? data[options.responseMap] : data); }))
                .subscribe(function (data) {
                state.dataState.data$.next(data);
                state.dataState.isData$.next(!_.isEmpty(data));
                state.dataState.loading$.next(false);
                state.requestState.pending = false;
                state.requestState.cachedAt = currentTime;
            }, function (err) {
                state.dataState.isData$.next(false);
                state.dataState.data$.error(null);
                state.dataState.loading$.next(false);
                state.requestState.pending = false;
            });
        }
        else {
            state.dataState.loading$.next(false);
        }
        return state.dataState;
    };
    ClientService.prototype.initState = function (key, options) {
        if (!this.state.has(key)) {
            this.state.set(key, {
                dataState: {
                    loading$: new BehaviorSubject(true),
                    isData$: new BehaviorSubject(false),
                    data$: new BehaviorSubject(null)
                },
                requestState: {
                    cachedAt: 0,
                    pending: false
                }
            });
        }
        else {
            this.state.get(key).dataState.loading$.next(true);
        }
    };
    ClientService.prototype.getHttpOptions = function (options) {
        var authorizationRequired = _.has(options, 'authorizationRequired')
            ? options.authorizationRequired
            : true;
        var etag = (options && options.etag) || undefined;
        var httpOptions = {
            headers: this.getHeaders(authorizationRequired, etag)
        };
        if (_.has(options, 'headers')) {
            // tslint:disable
            for (var key in options.headers) {
                httpOptions.headers[key] = options.headers[key];
            }
            // tslint:enable
        }
        if (_.has(options, 'params')) {
            httpOptions.params = options.params;
        }
        if (_.has(options, 'reportProgress')) {
            httpOptions.reportProgress = options.reportProgress;
        }
        return httpOptions;
    };
    ClientService.prototype.getHeaders = function (authorizationRequired, etag) {
        var headers = {
            'Content-Type': 'application/json'
        };
        if (authorizationRequired) {
            headers['Authorization'] = "Bearer " + this.getToken();
        }
        if (etag) {
            headers['ETag'] = etag;
        }
        return headers;
    };
    ClientService.prototype.getUrl = function (endpoint) {
        return "" + this.baseUrl + endpoint;
    };
    ClientService.prototype.getToken = function () {
        return localStorage.getItem(this.authToken);
    };
    ClientService.prototype.handleError = function (error) {
        if (error.error instanceof ErrorEvent) {
            // A client-side or network error occurred. Handle it accordingly.
            console.error('An error occurred:', error.error.message);
        }
        else {
            // The backend returned an unsuccessful response code.
            // The response body may contain clues as to what went wrong,
            console.error("Backend returned code " + error.status + ", " + ("body was: " + error.error));
        }
        // return an observable with a user-facing error message
        return throwError('Something bad happened; please try again later.');
    };
    ClientService.decorators = [
        { type: Injectable, args: [{
                    providedIn: 'root'
                },] }
    ];
    /** @nocollapse */
    ClientService.ctorParameters = function () { return [
        { type: undefined, decorators: [{ type: Inject, args: ['config',] }] },
        { type: HttpClient }
    ]; };
    ClientService.ngInjectableDef = i0.defineInjectable({ factory: function ClientService_Factory() { return new ClientService(i0.inject("config"), i0.inject(i1.HttpClient)); }, token: ClientService, providedIn: "root" });
    return ClientService;
}());
export { ClientService };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xpZW50LnNlcnZpY2UuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9AY29zcGhlcmUvY2xpZW50LyIsInNvdXJjZXMiOlsic2VydmljZXMvY2xpZW50LnNlcnZpY2UudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDbkQsT0FBTyxFQUNMLFVBQVUsRUFJWCxNQUFNLHNCQUFzQixDQUFDO0FBQzlCLE9BQU8sRUFBRSxlQUFlLEVBQXVCLFVBQVUsRUFBRSxNQUFNLE1BQU0sQ0FBQztBQUN4RSxPQUFPLEVBQUUsVUFBVSxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQztBQUN4RCxPQUFPLEtBQUssQ0FBQyxNQUFNLFlBQVksQ0FBQzs7O0FBS2hDO0lBcUJFLHVCQUFzQyxNQUFjLEVBQVUsSUFBZ0I7UUFBeEMsV0FBTSxHQUFOLE1BQU0sQ0FBUTtRQUFVLFNBQUksR0FBSixJQUFJLENBQVk7UUFqQjlFOztXQUVHO1FBQ0gsVUFBSyxHQUFHLElBQUksR0FBRyxFQUFzQixDQUFDO1FBS3JCLHFCQUFnQixHQUFXLFlBQVksQ0FBQztRQUV6RDs7OztXQUlHO1FBQ2MsY0FBUyxHQUFHLElBQUksR0FBRyxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUMsVUFBVTtRQUdyRCxJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO1FBQ25DLElBQUksQ0FBQyxTQUFTO1lBQ1osSUFBSSxDQUFDLE1BQU0sQ0FBQyxTQUFTLElBQUksSUFBSSxDQUFDLGdCQUFnQixDQUFDO0lBQ25ELENBQUM7SUFFRCwyQkFBRyxHQUFILFVBQU8sUUFBZ0IsRUFBRSxPQUFpQjtRQUN4QyxJQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ2xDLElBQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMs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QztvQkFDVixVQUFVLEVBQUUsTUFBTTtpQkFDbkI7Ozs7Z0RBbUJjLE1BQU0sU0FBQyxRQUFRO2dCQWpDNUIsVUFBVTs7O3dCQUZaO0NBb09DLEFBdE5ELElBc05DO1NBbk5ZLGFBQWEiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBJbmplY3QgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7XG4gIEh0dHBDbGllbnQsXG4gIEh0dHBQYXJhbXMsXG4gIEh0dHBIZWFkZXJzLFxuICBIdHRwRXJyb3JSZXNwb25zZVxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBCZWhhdmlvclN1YmplY3QsIFN1YmplY3QsIE9ic2VydmFibGUsIHRocm93RXJyb3IgfSBmcm9tICdyeGpzJztcbmltcG9ydCB7IGNhdGNoRXJyb3IsIHJldHJ5LCBtYXAgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDb25maWcgfSBmcm9tICcuL2NvbmZpZy5zZXJ2aWNlJztcbmltcG9ydCB7IE9wdGlvbnMsIFN0YXRlLCBEYXRhU3RhdGUsIFJlcXVlc3RTdGF0ZSB9IGZyb20gJy4vY2xpZW50LmludGVyZmFjZSc7XG5cbkBJbmplY3RhYmxlKHtcbiAgcHJvdmlkZWRJbjogJ3Jvb3QnXG59KVxuZXhwb3J0IGNsYXNzIENsaWVudFNlcnZpY2Uge1xuICAvKipcbiAgICogU3RhdGUgZm9yIGFsbCBHRVQgcGF5bG9hZHNcbiAgICovXG4gIHN0YXRlID0gbmV3IE1hcDxzdHJpbmcsIFN0YXRlPGFueT4+KCk7XG5cbiAgcmVhZG9ubHkgYmFzZVVybDogc3RyaW5nO1xuICByZWFkb25seSBhdXRoVG9rZW46IHN0cmluZztcblxuICBwcml2YXRlIHJlYWRvbmx5IGRlZmF1bHRBdXRoVG9rZW46IHN0cmluZyA9ICdhdXRoX3Rva2VuJztcblxuICAvKipcbiAgICogQ2FjaGUgdGltZSAtIGV2ZXJ5IEdFVCByZXF1ZXN0IGlzIHRha2VuIG9ubHkgaWYgdGhlIGxhc3Qgb25lXG4gICAqIHdhcyBpbnZva2VkIG5vdCBlYXJsaWVyIHRoZW4gYGNhY2hlVGltZWAgbWlucyBhZ28uXG4gICAqIE9ubHkgc3VjY2Vzc2Z1bCByZXNwb25zZXMgYXJlIGNhY2hlZCAoMnh4KVxuICAgKi9cbiAgcHJpdmF0ZSByZWFkb25seSBjYWNoZVRpbWUgPSAxMDAwICogNjAgKiA2MDsgLy8gNjAgbWluc1xuXG4gIGNvbnN0cnVjdG9yKEBJbmplY3QoJ2NvbmZpZycpIHByaXZhdGUgY29uZmlnOiBDb25maWcsIHByaXZhdGUgaHR0cDogSHR0cENsaWVudCkge1xuICAgIHRoaXMuYmFzZVVybCA9IHRoaXMuY29uZmlnLmJhc2VVcmw7XG4gICAgdGhpcy5hdXRoVG9rZW4gPVxuICAgICAgdGhpcy5jb25maWcuYXV0aFRva2VuIHx8IHRoaXMuZGVmYXVsdEF1dGhUb2tlbjtcbiAgfVxuXG4gIGdldDxUPihlbmRwb2ludDogc3RyaW5nLCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLmdldCh1cmwsIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBwb3N0PFQ+KGVuZHBvaW50OiBzdHJpbmcsIGJvZHk6IGFueSwgb3B0aW9ucz86IE9wdGlvbnMpOiBPYnNlcnZhYmxlPFQ+IHtcbiAgICBjb25zdCB1cmwgPSB0aGlzLmdldFVybChlbmRwb2ludCk7XG4gICAgY29uc3QgaHR0cE9wdGlvbnMgPSB0aGlzLmdldEh0dHBPcHRpb25zKG9wdGlvbnMpO1xuICAgIHJldHVybiB0aGlzLmh0dHBcbiAgICAgIC5wb3N0KHVybCwgYm9keSwgaHR0cE9wdGlvbnMpXG4gICAgICAucGlwZShyZXRyeSgzKSwgY2F0Y2hFcnJvcih0aGlzLmhhbmRsZUVycm9yKSkgYXMgT2JzZXJ2YWJsZTxUPjtcbiAgfVxuXG4gIHB1dDxUPihlbmRwb2ludDogc3RyaW5nLCBib2R5OiBhbnksIG9wdGlvbnM/OiBPcHRpb25zKTogT2JzZXJ2YWJsZTxUPiB7XG4gICAgY29uc3QgdXJsID0gdGhpcy5nZXRVcmwoZW5kcG9pbnQpO1xuICAgIGNvbnN0IGh0dHBPcHRpb25zID0gdGhpcy5nZXRIdHRwT3B0aW9ucyhvcHRpb25zKTtcbiAgICByZXR1cm4gdGhpcy5odHRwXG4gICAgICAucHV0KHVybCwgYm9keSwgaHR0cE9wdGlvbnMpXG4gICAgICAucGlwZShyZXRyeSgzKSwgY2F0Y2hFcnJvcih0aGlzLmhhbmRsZUVycm9yKSkgYXMgT2JzZXJ2YWJsZTxUPjtcbiAgfVxuXG4gIGRlbGV0ZTxUPihlbmRwb2ludDogc3RyaW5nLCBvcHRpb25zPzogT3B0aW9ucyk6IE9ic2VydmFibGU8VD4ge1xuICAgIGNvbnN0IHVybCA9IHRoaXMuZ2V0VXJsKGVuZHBvaW50KTtcbiAgICBjb25zdCBodHRwT3B0aW9ucyA9IHRoaXMuZ2V0SHR0cE9wdGlvbnMob3B0aW9ucyk7XG4gICAgcmV0dXJuIHRoaXMuaHR0cFxuICAgICAgLmRlbGV0ZSh1cmwsIGh0dHBPcHRpb25zKVxuICAgICAgLnBpcGUocmV0cnkoMyksIGNhdGNoRXJyb3IodGhpcy5oYW5kbGVFcnJvcikpIGFzIE9ic2VydmFibGU8VD47XG4gIH1cblxuICBnZXREYXRhU3RhdGU8VD4oZW5kcG9pbnQ6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiBEYXRhU3RhdGU8VD4ge1xuICAgIGNvbnN0IGtleSA9IG9wdGlvbnMgJiYgb3B0aW9ucy5wYXJhbXMgPyBgJHtlbmRwb2ludH1fJHtKU09OLnN0cmluZ2lmeShvcHRpb25zLnBhcmFtcyl9YCA6IGVuZHBvaW50O1xuICAgIHRoaXMuaW5pdFN0YXRlKGtleSwgb3B0aW9ucyk7XG5cbiAgICBsZXQgY2FjaGUgPSB0cnVlO1xuICAgIGxldCBwYXJhbXM6IEh0dHBQYXJhbXMgfCB7IFtwYXJhbTogc3RyaW5nXTogc3RyaW5nIHwgc3RyaW5nW10gfTtcblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAnY2FjaGUnKSkge1xuICAgICAgY2FjaGUgPSBvcHRpb25zLmNhY2hlO1xuICAgIH1cblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAncGFyYW1zJykpIHtcbiAgICAgIHBhcmFtcyA9IG9wdGlvbnMucGFyYW1zO1xuICAgIH1cblxuICAgIC8vIEdldCB0aGUgZW5kcG9pbnQgc3RhdGVcbiAgICBjb25zdCBzdGF0ZSA9IHRoaXMuc3RhdGUuZ2V0KGtleSk7XG5cbiAgICAvLyBEbyBub3QgYWxsb3cgaW52b2tlIHRoZSBzYW1lIEdFVCByZXF1ZXN0IHdoaWxlIG9uZSBpcyBwZW5kaW5nXG4gICAgaWYgKHN0YXRlLnJlcXVlc3RTdGF0ZS5wZW5kaW5nIC8qJiYgIV8uaXNFbXB0eShwYXJhbXMpKi8pIHtcbiAgICAgIHJldHVybiBzdGF0ZS5kYXRhU3RhdGU7XG4gICAgfVxuXG4gICAgY29uc3QgY3VycmVudFRpbWUgPSArbmV3IERhdGUoKTtcbiAgICBpZiAoXG4gICAgICBjdXJyZW50VGltZSAtIHN0YXRlLnJlcXVlc3RTdGF0ZS5jYWNoZWRBdCA+IHRoaXMuY2FjaGVUaW1lIHx8XG4gICAgICAvLyAhXy5pc0VtcHR5KHBhcmFtcykgfHxcbiAgICAgICFjYWNoZVxuICAgICkge1xuICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLnBlbmRpbmcgPSB0cnVlO1xuICAgICAgdGhpcy5nZXQoZW5kcG9pbnQsIG9wdGlvbnMpXG4gICAgICAgIC5waXBlKFxuICAgICAgICAgIG1hcChkYXRhID0+IChvcHRpb25zLnJlc3BvbnNlTWFwID8gZGF0YVtvcHRpb25zLnJlc3BvbnNlTWFwXSA6IGRhdGEpKVxuICAgICAgICApXG4gICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgZGF0YSA9PiB7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuZGF0YSQubmV4dChkYXRhKTtcbiAgICAgICAgICAgIHN0YXRlLmRhdGFTdGF0ZS5pc0RhdGEkLm5leHQoIV8uaXNFbXB0eShkYXRhKSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUubG9hZGluZyQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyA9IGZhbHNlO1xuICAgICAgICAgICAgc3RhdGUucmVxdWVzdFN0YXRlLmNhY2hlZEF0ID0gY3VycmVudFRpbWU7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgc3RhdGUuZGF0YVN0YXRlLmlzRGF0YSQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUuZGF0YSQuZXJyb3IobnVsbCk7XG4gICAgICAgICAgICBzdGF0ZS5kYXRhU3RhdGUubG9hZGluZyQubmV4dChmYWxzZSk7XG4gICAgICAgICAgICBzdGF0ZS5yZXF1ZXN0U3RhdGUucGVuZGluZyA9IGZhbHNlO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc3RhdGUuZGF0YVN0YXRlLmxvYWRpbmckLm5leHQoZmFsc2UpO1xuICAgIH1cblxuICAgIHJldHVybiBzdGF0ZS5kYXRhU3RhdGU7XG4gIH1cblxuICBwcml2YXRlIGluaXRTdGF0ZShrZXk6IHN0cmluZywgb3B0aW9ucz86IE9wdGlvbnMpOiB2b2lkIHtcbiAgICBpZiAoIXRoaXMuc3RhdGUuaGFzKGtleSkpIHtcbiAgICAgIHRoaXMuc3RhdGUuc2V0KGtleSwge1xuICAgICAgICBkYXRhU3RhdGU6IHtcbiAgICAgICAgICBsb2FkaW5nJDogbmV3IEJlaGF2aW9yU3ViamVjdCh0cnVlKSxcbiAgICAgICAgICBpc0RhdGEkOiBuZXcgQmVoYXZpb3JTdWJqZWN0KGZhbHNlKSxcbiAgICAgICAgICBkYXRhJDogbmV3IEJlaGF2aW9yU3ViamVjdChudWxsKVxuICAgICAgICB9LFxuICAgICAgICByZXF1ZXN0U3RhdGU6IHtcbiAgICAgICAgICBjYWNoZWRBdDogMCxcbiAgICAgICAgICBwZW5kaW5nOiBmYWxzZVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5zdGF0ZS5nZXQoa2V5KS5kYXRhU3RhdGUubG9hZGluZyQubmV4dCh0cnVlKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGdldEh0dHBPcHRpb25zKFxuICAgIG9wdGlvbnM/OiBPcHRpb25zXG4gICk6IHtcbiAgICBwYXJhbXM/OiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgaGVhZGVycz86IEh0dHBIZWFkZXJzIHwgeyBbaGVhZGVyOiBzdHJpbmddOiBzdHJpbmcgfCBzdHJpbmdbXSB9O1xuICAgIHJlcG9ydFByb2dyZXNzPzogYm9vbGVhbjtcbiAgfSB7XG4gICAgY29uc3QgYXV0aG9yaXphdGlvblJlcXVpcmVkID0gXy5oYXMob3B0aW9ucywgJ2F1dGhvcml6YXRpb25SZXF1aXJlZCcpXG4gICAgICA/IG9wdGlvbnMuYXV0aG9yaXphdGlvblJlcXVpcmVkXG4gICAgICA6IHRydWU7XG4gICAgY29uc3QgZXRhZyA9IChvcHRpb25zICYmIG9wdGlvbnMuZXRhZykgfHwgdW5kZWZpbmVkO1xuXG4gICAgbGV0IGh0dHBPcHRpb25zOiB7XG4gICAgICBwYXJhbXM/OiBIdHRwUGFyYW1zIHwgeyBbcGFyYW06IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgICBoZWFkZXJzPzogSHR0cEhlYWRlcnMgfCB7IFtoZWFkZXI6IHN0cmluZ106IHN0cmluZyB8IHN0cmluZ1tdIH07XG4gICAgICByZXBvcnRQcm9ncmVzcz86IGJvb2xlYW47XG4gICAgfSA9IHtcbiAgICAgIGhlYWRlcnM6IHRoaXMuZ2V0SGVhZGVycyhhdXRob3JpemF0aW9uUmVxdWlyZWQsIGV0YWcpXG4gICAgfTtcblxuICAgIGlmIChfLmhhcyhvcHRpb25zLCAnaGVhZGVycycpKSB7XG4gICAgICAvLyB0c2xpbnQ6ZGlzYWJsZVxuICAgICAgZm9yIChsZXQga2V5IGluIG9wdGlvbnMuaGVhZGVycykge1xuICAgICAgICBodHRwT3B0aW9ucy5oZWFkZXJzW2tleV0gPSAoPGFueT5vcHRpb25zKS5oZWFkZXJzW2tleV07XG4gICAgICB9XG4gICAgICAvLyB0c2xpbnQ6ZW5hYmxlXG4gICAgfVxuXG4gICAgaWYgKF8uaGFzKG9wdGlvbnMsICdwYXJhbXMnKSkge1xuICAgICAgaHR0cE9wdGlvbnMucGFyYW1zID0gb3B0aW9ucy5wYXJhbXM7XG4gICAgfVxuXG4gICAgaWYgKF8uaGFzKG9wdGlvbnMsICdyZXBvcnRQcm9ncmVzcycpKSB7XG4gICAgICBodHRwT3B0aW9ucy5yZXBvcnRQcm9ncmVzcyA9IG9wdGlvbnMucmVwb3J0UHJvZ3Jlc3M7XG4gICAgfVxuXG4gICAgcmV0dXJuIGh0dHBPcHRpb25zO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRIZWFkZXJzKFxuICAgIGF1dGhvcml6YXRpb25SZXF1aXJlZDogYm9vbGVhbixcbiAgICBldGFnPzogc3RyaW5nXG4gICk6IHsgW2tleTogc3RyaW5nXTogc3RyaW5nIH0ge1xuICAgIGxldCBoZWFkZXJzID0ge1xuICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJ1xuICAgIH07XG5cbiAgICBpZiAoYXV0aG9yaXphdGlvblJlcXVpcmVkKSB7XG4gICAgICBoZWFkZXJzWydBdXRob3JpemF0aW9uJ10gPSBgQmVhcmVyICR7dGhpcy5nZXRUb2tlbigpfWA7XG4gICAgfVxuXG4gICAgaWYgKGV0YWcpIHtcbiAgICAgIGhlYWRlcnNbJ0VUYWcnXSA9IGV0YWc7XG4gICAgfVxuXG4gICAgcmV0dXJuIGhlYWRlcnM7XG4gIH1cblxuICBwcml2YXRlIGdldFVybChlbmRwb2ludDogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gYCR7dGhpcy5iYXNlVXJsfSR7ZW5kcG9pbnR9YDtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0VG9rZW4oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0odGhpcy5hdXRoVG9rZW4pO1xuICB9XG5cbiAgcHJpdmF0ZSBoYW5kbGVFcnJvcihlcnJvcjogSHR0cEVycm9yUmVzcG9uc2UpIHtcbiAgICBpZiAoZXJyb3IuZXJyb3IgaW5zdGFuY2VvZiBFcnJvckV2ZW50KSB7XG4gICAgICAvLyBBIGNsaWVudC1zaWRlIG9yIG5ldHdvcmsgZXJyb3Igb2NjdXJyZWQuIEhhbmRsZSBpdCBhY2NvcmRpbmdseS5cbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0FuIGVycm9yIG9jY3VycmVkOicsIGVycm9yLmVycm9yLm1lc3NhZ2UpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBUaGUgYmFja2VuZCByZXR1cm5lZCBhbiB1bnN1Y2Nlc3NmdWwgcmVzcG9uc2UgY29kZS5cbiAgICAgIC8vIFRoZSByZXNwb25zZSBib2R5IG1heSBjb250YWluIGNsdWVzIGFzIHRvIHdoYXQgd2VudCB3cm9uZyxcbiAgICAgIGNvbnNvbGUuZXJyb3IoXG4gICAgICAgIGBCYWNrZW5kIHJldHVybmVkIGNvZGUgJHtlcnJvci5zdGF0dXN9LCBgICsgYGJvZHkgd2FzOiAke2Vycm9yLmVycm9yfWBcbiAgICAgICk7XG4gICAgfVxuXG4gICAgLy8gcmV0dXJuIGFuIG9ic2VydmFibGUgd2l0aCBhIHVzZXItZmFjaW5nIGVycm9yIG1lc3NhZ2VcbiAgICByZXR1cm4gdGhyb3dFcnJvcignU29tZXRoaW5nIGJhZCBoYXBwZW5lZDsgcGxlYXNlIHRyeSBhZ2FpbiBsYXRlci4nKTtcbiAgfVxufVxuIl19