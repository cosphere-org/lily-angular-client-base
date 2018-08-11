import { Observable } from 'rxjs';
import { ClientService } from '../../services/client.service';
import { DataState } from '../../services/client.interface';
import * as X from './quizzer.models';
export declare class QuizzerDomain {
    private client;
    constructor(client: ClientService);
    /**
     * Build Read Quiz Attempts
     */
    bulkReadQuizattempts(quizId: any): DataState<X.BulkReadQuizattemptsResponseEntity[]>;
    bulkReadQuizattempts2(quizId: any): Observable<X.BulkReadQuizattemptsResponseEntity[]>;
    /**
     * Bulk Read Quizzes
     */
    bulkReadQuizzes(): DataState<X.BulkReadQuizzesResponseEntity[]>;
    bulkReadQuizzes2(): Observable<X.BulkReadQuizzesResponseEntity[]>;
    /**
     * Create Quiz
     */
    createQuiz(body: X.CreateQuizBody): Observable<X.CreateQuizResponse>;
    /**
     * Create Quiz Attempt
     */
    createQuizattempt(quizId: any, body: X.CreateQuizattemptBody): Observable<X.CreateQuizattemptResponse>;
    /**
     * Delete Quiz
     */
    deleteQuiz(quizId: any): Observable<X.DeleteQuizResponse>;
    /**
     * Read Quiz
     */
    readQuiz(quizId: any): DataState<X.ReadQuizResponse>;
    readQuiz2(quizId: any): Observable<X.ReadQuizResponse>;
    /**
     * Update Quiz
     */
    updateQuiz(quizId: any, body: X.UpdateQuizBody): Observable<X.UpdateQuizResponse>;
}
