/**
  * THIS FILE WAS AUTOGENERATED, ALL MANUAL CHANGES CAN BE
  * OVERWRITTEN
  */
/**
 * Quizzer Entities Management Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import * as _ from 'underscore';
import { ClientService } from '../../services/client.service';
var QuizzerDomain = /** @class */ (function () {
    function QuizzerDomain(client) {
        this.client = client;
    }
    /**
     * Build Read Quiz Attempts
     */
    QuizzerDomain.prototype.bulkReadQuizattempts = function (quizId) {
        return this.client.getDataState("/quizzes/" + quizId + "/attempts/", { responseMap: 'data', authorizationRequired: true });
    };
    QuizzerDomain.prototype.bulkReadQuizattempts2 = function (quizId) {
        return this.client.get("/quizzes/" + quizId + "/attempts/", { responseMap: 'data', authorizationRequired: true });
    };
    /**
     * Bulk Read Quizzes
     */
    QuizzerDomain.prototype.bulkReadQuizzes = function () {
        return this.client.getDataState('/quizzes/', { responseMap: 'data', authorizationRequired: true });
    };
    QuizzerDomain.prototype.bulkReadQuizzes2 = function () {
        return this.client.get('/quizzes/', { responseMap: 'data', authorizationRequired: true });
    };
    /**
     * Create Quiz
     */
    QuizzerDomain.prototype.createQuiz = function (body) {
        return this.client
            .post('/quizzes/', body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Create Quiz Attempt
     */
    QuizzerDomain.prototype.createQuizattempt = function (quizId, body) {
        return this.client
            .post("/quizzes/" + quizId + "/attempts/", body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Delete Quiz
     */
    QuizzerDomain.prototype.deleteQuiz = function (quizId) {
        return this.client
            .delete("/quizzes/" + quizId, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    /**
     * Read Quiz
     */
    QuizzerDomain.prototype.readQuiz = function (quizId) {
        return this.client.getDataState("/quizzes/" + quizId, { authorizationRequired: true });
    };
    QuizzerDomain.prototype.readQuiz2 = function (quizId) {
        return this.client.get("/quizzes/" + quizId, { authorizationRequired: true });
    };
    /**
     * Update Quiz
     */
    QuizzerDomain.prototype.updateQuiz = function (quizId, body) {
        return this.client
            .put("/quizzes/" + quizId, body, { authorizationRequired: true })
            .pipe(filter(function (x) { return !_.isEmpty(x); }));
    };
    QuizzerDomain.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    QuizzerDomain.ctorParameters = function () { return [
        { type: ClientService }
    ]; };
    return QuizzerDomain;
}());
export { QuizzerDomain };

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicXVpenplci5kb21haW4uanMiLCJzb3VyY2VSb290Ijoibmc6Ly9AY29zcGhlcmUvY2xpZW50LyIsInNvdXJjZXMiOlsiZG9tYWlucy9xdWl6emVyL3F1aXp6ZXIuZG9tYWluLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7SUFHSTtBQUVKOztHQUVHO0FBQ0gsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUMzQyxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFFeEMsT0FBTyxLQUFLLENBQUMsTUFBTSxZQUFZLENBQUM7QUFFaEMsT0FBTyxFQUFFLGFBQWEsRUFBRSxNQUFNLCtCQUErQixDQUFDO0FBSzlEO0lBRUksdUJBQW9CLE1BQXFCO1FBQXJCLFdBQU0sR0FBTixNQUFNLENBQWU7SUFBRyxDQUFDO0lBRTdDOztPQUVHO0lBQ0ksNENBQW9CLEdBQTNCLFVBQTRCLE1BQVc7UUFDbkMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUF5QyxjQUFZLE1BQU0sZUFBWSxFQUFFLEVBQUUsV0FBVyxFQUFFLE1BQU0sRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ2xLLENBQUM7SUFFTSw2Q0FBcUIsR0FBNUIsVUFBNkIsTUFBVztRQUNwQyxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQXlDLGNBQVksTUFBTSxlQUFZLEVBQUUsRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDekosQ0FBQztJQUVEOztPQUVHO0lBQ0ksdUNBQWUsR0FBdEI7UUFDSSxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQW9DLFdBQVcsRUFBRSxFQUFFLFdBQVcsRUFBRSxNQUFNLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUMxSSxDQUFDO0lBRU0sd0NBQWdCLEdBQXZCO1FBQ0ksTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFvQyxXQUFXLEVBQUUsRUFBRSxXQUFXLEVBQUUsTUFBTSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFDakksQ0FBQztJQUVEOztPQUVHO0lBQ0ksa0NBQVUsR0FBakIsVUFBa0IsSUFBc0I7UUFDcEMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUF1QixXQUFXLEVBQUUsSUFBSSxFQUFFLEVBQUUscUJBQXFCLEVBQUUsSUFBSSxFQUFFLENBQUM7YUFDOUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFBLENBQUMsSUFBSSxPQUFBLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBYixDQUFhLENBQUMsQ0FBQyxDQUFDO0lBQzFDLENBQUM7SUFFRDs7T0FFRztJQUNJLHlDQUFpQixHQUF4QixVQUF5QixNQUFXLEVBQUUsSUFBNkI7UUFDL0QsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNO2FBQ2IsSUFBSSxDQUE4QixjQUFZLE1BQU0sZUFBWSxFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDO2FBQ3hHLElBQUksQ0FBQyxNQUFNLENBQUMsVUFBQSxDQUFDLElBQUksT0FBQSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLEVBQWIsQ0FBYSxDQUFDLENBQUMsQ0FBQztJQUMxQyxDQUFDO0lBRUQ7O09BRUc7SUFDSSxrQ0FBVSxHQUFqQixVQUFrQixNQUFXO1FBQ3pCLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTTthQUNiLE1BQU0sQ0FBdUIsY0FBWSxNQUFRLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQzthQUNuRixJQUFJLENBQUMsTUFBTSxDQUFDLFVBQUEsQ0FBQyxJQUFJLE9BQUEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFiLENBQWEsQ0FBQyxDQUFDLENBQUM7SUFDMUMsQ0FBQztJQUVEOztPQUVHO0lBQ0ksZ0NBQVEsR0FBZixVQUFnQixNQUFXO1FBQ3ZCLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBcUIsY0FBWSxNQUFRLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQy9HLENBQUM7SUFFTSxpQ0FBUyxHQUFoQixVQUFpQixNQUFXO1FBQ3hCLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBcUIsY0FBWSxNQUFRLEVBQUUsRUFBRSxxQkFBcUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0lBQ3RHLENBQUM7SUFFRDs7T0FFRztJQUNJLGtDQUFVLEdBQWpCLFVBQWtCLE1BQVcsRUFBRSxJQUFzQjtRQUNqRCxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU07YUFDYixHQUFHLENBQXVCLGNBQVksTUFBUSxFQUFFLElBQUksRUFBRSxFQUFFLHFCQUFxQixFQUFFLElBQUksRUFBRSxDQUFDO2FBQ3RGLElBQUksQ0FBQyxNQUFNLENBQUMsVUFBQSxDQUFDLElBQUksT0FBQSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLEVBQWIsQ0FBYSxDQUFDLENBQUMsQ0FBQztJQUMxQyxDQUFDOztnQkF2RUosVUFBVTs7OztnQkFMRixhQUFhOztJQThFdEIsb0JBQUM7Q0FBQSxBQXpFRCxJQXlFQztTQXhFWSxhQUFhIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gICogVEhJUyBGSUxFIFdBUyBBVVRPR0VORVJBVEVELCBBTEwgTUFOVUFMIENIQU5HRVMgQ0FOIEJFXG4gICogT1ZFUldSSVRURU5cbiAgKi9cblxuLyoqXG4gKiBRdWl6emVyIEVudGl0aWVzIE1hbmFnZW1lbnQgRG9tYWluXG4gKi9cbmltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7IGZpbHRlciB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJztcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJztcbmltcG9ydCAqIGFzIF8gZnJvbSAndW5kZXJzY29yZSc7XG5cbmltcG9ydCB7IENsaWVudFNlcnZpY2UgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuc2VydmljZSc7XG5pbXBvcnQgeyBEYXRhU3RhdGUgfSBmcm9tICcuLi8uLi9zZXJ2aWNlcy9jbGllbnQuaW50ZXJmYWNlJztcblxuaW1wb3J0ICogYXMgWCBmcm9tICcuL3F1aXp6ZXIubW9kZWxzJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFF1aXp6ZXJEb21haW4ge1xuICAgIGNvbnN0cnVjdG9yKHByaXZhdGUgY2xpZW50OiBDbGllbnRTZXJ2aWNlKSB7fVxuXG4gICAgLyoqXG4gICAgICogQnVpbGQgUmVhZCBRdWl6IEF0dGVtcHRzXG4gICAgICovXG4gICAgcHVibGljIGJ1bGtSZWFkUXVpemF0dGVtcHRzKHF1aXpJZDogYW55KTogRGF0YVN0YXRlPFguQnVsa1JlYWRRdWl6YXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXREYXRhU3RhdGU8WC5CdWxrUmVhZFF1aXphdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+KGAvcXVpenplcy8ke3F1aXpJZH0vYXR0ZW1wdHMvYCwgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuICAgIFxuICAgIHB1YmxpYyBidWxrUmVhZFF1aXphdHRlbXB0czIocXVpeklkOiBhbnkpOiBPYnNlcnZhYmxlPFguQnVsa1JlYWRRdWl6YXR0ZW1wdHNSZXNwb25zZUVudGl0eVtdPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5CdWxrUmVhZFF1aXphdHRlbXB0c1Jlc3BvbnNlRW50aXR5W10+KGAvcXVpenplcy8ke3F1aXpJZH0vYXR0ZW1wdHMvYCwgeyByZXNwb25zZU1hcDogJ2RhdGEnLCBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogQnVsayBSZWFkIFF1aXp6ZXNcbiAgICAgKi9cbiAgICBwdWJsaWMgYnVsa1JlYWRRdWl6emVzKCk6IERhdGFTdGF0ZTxYLkJ1bGtSZWFkUXVpenplc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLkJ1bGtSZWFkUXVpenplc1Jlc3BvbnNlRW50aXR5W10+KCcvcXVpenplcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIGJ1bGtSZWFkUXVpenplczIoKTogT2JzZXJ2YWJsZTxYLkJ1bGtSZWFkUXVpenplc1Jlc3BvbnNlRW50aXR5W10+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldDxYLkJ1bGtSZWFkUXVpenplc1Jlc3BvbnNlRW50aXR5W10+KCcvcXVpenplcy8nLCB7IHJlc3BvbnNlTWFwOiAnZGF0YScsIGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBDcmVhdGUgUXVpelxuICAgICAqL1xuICAgIHB1YmxpYyBjcmVhdGVRdWl6KGJvZHk6IFguQ3JlYXRlUXVpekJvZHkpOiBPYnNlcnZhYmxlPFguQ3JlYXRlUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudFxuICAgICAgICAgICAgLnBvc3Q8WC5DcmVhdGVRdWl6UmVzcG9uc2U+KCcvcXVpenplcy8nLCBib2R5LCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIENyZWF0ZSBRdWl6IEF0dGVtcHRcbiAgICAgKi9cbiAgICBwdWJsaWMgY3JlYXRlUXVpemF0dGVtcHQocXVpeklkOiBhbnksIGJvZHk6IFguQ3JlYXRlUXVpemF0dGVtcHRCb2R5KTogT2JzZXJ2YWJsZTxYLkNyZWF0ZVF1aXphdHRlbXB0UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucG9zdDxYLkNyZWF0ZVF1aXphdHRlbXB0UmVzcG9uc2U+KGAvcXVpenplcy8ke3F1aXpJZH0vYXR0ZW1wdHMvYCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbiAgICAvKipcbiAgICAgKiBEZWxldGUgUXVpelxuICAgICAqL1xuICAgIHB1YmxpYyBkZWxldGVRdWl6KHF1aXpJZDogYW55KTogT2JzZXJ2YWJsZTxYLkRlbGV0ZVF1aXpSZXNwb25zZT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5jbGllbnRcbiAgICAgICAgICAgIC5kZWxldGU8WC5EZWxldGVRdWl6UmVzcG9uc2U+KGAvcXVpenplcy8ke3F1aXpJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KVxuICAgICAgICAgICAgLnBpcGUoZmlsdGVyKHggPT4gIV8uaXNFbXB0eSh4KSkpO1xuICAgIH1cblxuICAgIC8qKlxuICAgICAqIFJlYWQgUXVpelxuICAgICAqL1xuICAgIHB1YmxpYyByZWFkUXVpeihxdWl6SWQ6IGFueSk6IERhdGFTdGF0ZTxYLlJlYWRRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50LmdldERhdGFTdGF0ZTxYLlJlYWRRdWl6UmVzcG9uc2U+KGAvcXVpenplcy8ke3F1aXpJZH1gLCB7IGF1dGhvcml6YXRpb25SZXF1aXJlZDogdHJ1ZSB9KTtcbiAgICB9XG4gICAgXG4gICAgcHVibGljIHJlYWRRdWl6MihxdWl6SWQ6IGFueSk6IE9ic2VydmFibGU8WC5SZWFkUXVpelJlc3BvbnNlPiB7XG4gICAgICAgIHJldHVybiB0aGlzLmNsaWVudC5nZXQ8WC5SZWFkUXVpelJlc3BvbnNlPihgL3F1aXp6ZXMvJHtxdWl6SWR9YCwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSk7XG4gICAgfVxuXG4gICAgLyoqXG4gICAgICogVXBkYXRlIFF1aXpcbiAgICAgKi9cbiAgICBwdWJsaWMgdXBkYXRlUXVpeihxdWl6SWQ6IGFueSwgYm9keTogWC5VcGRhdGVRdWl6Qm9keSk6IE9ic2VydmFibGU8WC5VcGRhdGVRdWl6UmVzcG9uc2U+IHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY2xpZW50XG4gICAgICAgICAgICAucHV0PFguVXBkYXRlUXVpelJlc3BvbnNlPihgL3F1aXp6ZXMvJHtxdWl6SWR9YCwgYm9keSwgeyBhdXRob3JpemF0aW9uUmVxdWlyZWQ6IHRydWUgfSlcbiAgICAgICAgICAgIC5waXBlKGZpbHRlcih4ID0+ICFfLmlzRW1wdHkoeCkpKTtcbiAgICB9XG5cbn0iXX0=