/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Auth Tokens Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
var AuthTokensDomain = /** @class */ (function () {
    function AuthTokensDomain(client) {
        this.client = client;
    }
    /**
     * Authorize a given token
     * -------------
     *
     * Can be called by the API Gateway in order to authorize every request using provided token.
     */
    AuthTokensDomain.prototype.authorizeAuthToken = function () {
        return this.client
            .post('/auth/auth_tokens/authorize/', {}, { authorizationRequired: false })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Sign In
     * -------------
     *
     * Validates data provided on the input and if successful returns auth token.
     */
    AuthTokensDomain.prototype.createAuthToken = function (body) {
        return this.client
            .post('/auth/auth_tokens/', body, { authorizationRequired: false })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Facebook Auth Token
     */
    AuthTokensDomain.prototype.createFacebookBasedAuthToken = function (body) {
        return this.client
            .post('/auth/auth_tokens/facebook/', body, { authorizationRequired: false })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Mobile Facebook Auth Token
     */
    AuthTokensDomain.prototype.createFacebookBasedMobileAuthToken = function (body) {
        return this.client
            .post('/auth/auth_tokens/facebook/mobile/', body, { authorizationRequired: false })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Google Auth Token
     */
    AuthTokensDomain.prototype.createGoogleBasedAuthToken = function (body) {
        return this.client
            .post('/auth/auth_tokens/google/', body, { authorizationRequired: false })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Mobile Google Auth Token
     */
    AuthTokensDomain.prototype.createGoogleBasedMobileAuthToken = function (body) {
        return this.client
            .post('/auth/auth_tokens/google/mobile/', body, { authorizationRequired: false })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Refresh JWT token
     * -------------
     *
     * Should be used whenever token is close to expiry or if one is requested to refresh the token because for example account type was changed and new token should be requested to reflect that change.
     */
    AuthTokensDomain.prototype.updateAuthToken = function () {
        return this.client
            .put('/auth/auth_tokens/', {}, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    AuthTokensDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    AuthTokensDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return AuthTokensDomain;
}());
export { AuthTokensDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aF90b2tlbnMuZG9tYWluLmpzIiwic291cmNlUm9vdCI6Im5nOi8vQGNvc3BoZXJlL2NsaWVudC8iLCJzb3VyY2VzIjpbImRvbWFpbnMvYXV0aF90b2tlbnMvYXV0aF90b2tlbnMuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBSzlEO0lBRUksMEJBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7SUFBRyxDQUFDO0lBRTdDOzs7OztPQUtHO0lBQ0ksNkNBQWtCLEdBQXpCO1FBQ0ksTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUErQiw4QkFBOEIsRUFBRSxFQUFFLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQzthQUN4RyxJQUFJLENBQUMsTUFBTSxDQUFDLFVBQUEsQ0FBQyxJQUFJLE9BQUEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFiLENBQWEsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0ksMENBQWUsR0FBdEIsVUFBdUIsSUFBMkI7UUFDOUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUE0QixvQkFBb0IsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQzthQUM3RixJQUFJLENBQUMsTUFBTSxDQUFDLFVBQUEsQ0FBQyxJQUFJLE9BQUEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFiLENBQWEsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVEOztPQUVHO0lBQ0ksdURBQTRCLEdBQW5DLFVBQW9DLElBQXdDO1FBQ3hFLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBeUMsNkJBQTZCLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUM7YUFDbkgsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7SUFFRDs7T0FFRztJQUNJLDZEQUFrQyxHQUF6QyxVQUEwQyxJQUE4QztRQUNwRixNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU07YUFDYixJQUFJLENBQStDLG9DQUFvQyxFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLEtBQUssRUFBRSxDQUFDO2FBQ2hJLElBQUksQ0FBQyxNQUFNLENBQUMsVUFBQSxDQUFDLElBQUksT0FBQSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLEVBQWIsQ0FBYSxDQUFDLENBQUMsQ0FBQztJQUMxQyxDQUFDO0lBRUQ7O09BRUc7SUFDSSxxREFBMEIsR0FBakMsVUFBa0MsSUFBc0M7UUFDcEUsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUF1QywyQkFBMkIsRUFBRSxJQUFJLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxLQUFLLEVBQUUsQ0FBQzthQUMvRyxJQUFJLENBQUMsTUFBTSxDQUFDLFVBQUEsQ0FBQyxJQUFJLE9BQUEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFiLENBQWEsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVEOztPQUVHO0lBQ0ksMkRBQWdDLEdBQXZDLFVBQXdDLElBQTRDO1FBQ2hGLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLElBQUksQ0FBNkMsa0NBQWtDLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsS0FBSyxFQUFFLENBQUM7YUFDNUgsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNJLDBDQUFlLEdBQXRCO1FBQ0ksTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsR0FBRyxDQUE0QixvQkFBb0IsRUFBRSxFQUFFLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUN6RixJQUFJLENBQUMsTUFBTSxDQUFDLFVBQUEsQ0FBQyxJQUFJLE9BQUEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFiLENBQWEsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQzs7Z0JBMUVKLFVBQVU7Ozs7Z0JBTEYsYUFBYTs7SUFpRnRCLHVCQUFDO0NBQUEsQUE1RUQsSUE0RUM7U0EzRVksZ0JBQWdCIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBBdXRoIFRva2VucyBNYW5hZ2VtZW50IERvbWFpblxuICovXG5pbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5pbXBvcnQgeyBmaWx0ZXIgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgKiBhcyBfIGZyb20gJ3VuZGVyc2NvcmUnO1xuXG5pbXBvcnQgeyBDbGllbnRTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgRGF0YVN0YXRlIH0gZnJvbSAnLi4vLi4vc2VydmljZXMvY2xpZW50LmludGVyZmFjZSc7XG5cbmltcG9ydCAqIGFzIFggZnJvbSAnLi9hdXRoX3Rva2Vucy5tb2RlbHMnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQXV0aFRva2Vuc0RvbWFpbiB7XG4gICAgY29uc3RydWN0b3IocHJpdmF0ZSBjbGllbnQ6IENsaWVudFNlcnZpY2UpIHt9XG5cbiAgICAvKipcbiAgICAgKiBBdXRob3JpemUgYSBnaXZlbiB0b2tlblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIENhbiBiZSBjYWxsZWQgYnkgdGhlIEFQSSBHYXRld2F5IGluIG9yZGVyIHRvIGF1dGhvcml6ZSBldmVyeSByZXF1ZXN0IHVzaW5nIHByb3ZpZGVkIHRva2VuLlxuICAgICAqL1xuICAgIHB1YmxpYyBhdXRob3JpemVBdXRoVG9rZW4oKTogT2JzZXJ2YWJsZTxYLkF1dGhvcml6ZUF1dGhUb2tlblJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5BdXRob3JpemVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2F1dGhvcml6ZS8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogU2lnbiBJblxuICAgICAqIC0tLS0tLS0tLS0tLS1cbiAgICAgKlxuICAgICAqIFZhbGlkYXRlcyBkYXRhIHByb3ZpZGVkIG9uIHRoZSBpbnB1dCBhbmQgaWYgc3VjY2Vzc2Z1bCByZXR1cm5zIGF1dGggdG9rZW4uXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIEZhY2Vib29rIEF1dGggVG9rZW5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlbihib2R5OiBYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUZhY2Vib29rQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlRmFjZWJvb2tCYXNlZEF1dGhUb2tlblJlc3BvbnNlPignL2F1dGgvYXV0aF90b2tlbnMvZmFjZWJvb2svJywgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IGZhbHNlIH0pXG4gICAgICAgICAgICAucGlwZShmaWx0ZXIoeCA9PiAhXy5pc0VtcHR5KHgpKSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQ3JlYXRlIE1vYmlsZSBGYWNlYm9vayBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuQm9keSk6IE9ic2VydmFibGU8WC5DcmVhdGVGYWNlYm9va0Jhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUZhY2Vib29rQmFzZWRNb2JpbGVBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2ZhY2Vib29rL21vYmlsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgR29vZ2xlIEF1dGggVG9rZW5cbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW4oYm9keTogWC5DcmVhdGVHb29nbGVCYXNlZEF1dGhUb2tlbkJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5wb3N0PFguQ3JlYXRlR29vZ2xlQmFzZWRBdXRoVG9rZW5SZXNwb25zZT4oJy9hdXRoL2F1dGhfdG9rZW5zL2dvb2dsZS8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogZmFsc2UgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgTW9iaWxlIEdvb2dsZSBBdXRoIFRva2VuXG4gICAgICovXG4gICAgcHVibGljIGNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuKGJvZHk6IFguQ3JlYXRlR29vZ2xlQmFzZWRNb2JpbGVBdXRoVG9rZW5Cb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZUdvb2dsZUJhc2VkTW9iaWxlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy9nb29nbGUvbW9iaWxlLycsIGJvZHksIHsgYXV0aG9yaXphdGlvblJlcXVpcmVkOiBmYWxzZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlZnJlc2ggSldUIHRva2VuXG4gICAgICogLS0tLS0tLS0tLS0tLVxuICAgICAqXG4gICAgICogU2hvdWxkIGJlIHVzZWQgd2hlbmV2ZXIgdG9rZW4gaXMgY2xvc2UgdG8gZXhwaXJ5IG9yIGlmIG9uZSBpcyByZXF1ZXN0ZWQgdG8gcmVmcmVzaCB0aGUgdG9rZW4gYmVjYXVzZSBmb3IgZXhhbXBsZSBhY2NvdW50IHR5cGUgd2FzIGNoYW5nZWQgYW5kIG5ldyB0b2tlbiBzaG91bGQgYmUgcmVxdWVzdGVkIHRvIHJlZmxlY3QgdGhhdCBjaGFuZ2UuXG4gICAgICovXG4gICAgcHVibGljIHVwZGF0ZUF1dGhUb2tlbigpOiBPYnNlcnZhYmxlPFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlQXV0aFRva2VuUmVzcG9uc2U+KCcvYXV0aC9hdXRoX3Rva2Vucy8nLCB7fSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iXX0=