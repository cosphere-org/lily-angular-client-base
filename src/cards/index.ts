/**
 * Cards Domain
 */
import { filter, takeUntil } from 'rxjs/operators';
import { BehaviorSubject, Subject, Observable } from 'rxjs';
import * as _ from 'underscore';

import { HttpClient } from '../HttpClient';
import { Card } from './Models';


interface BulkReadCardsParams {
    limit?: number;

    offset?: number;

    query?: string;

    ids?: number[];

    category_id?: number;
}

export class CardsDomain {

    private http: HttpClient = new HttpClient();

    constructor(private baseUri: string, private http: HttpClient) {}

    public bulkReadCards(params?: BulkReadCardsParams): Observable<Card> {
        // FIXME: in the future this guy could be enriched by some nice
        // and automatic caching mechanism --> e.g. it would make a call only
        // if the OPTIONS responded by LAST-MODIFIED header and 304 -> that
        // would require on the Backend Side to store the info about the
        // freshness of particular resources -> or just a info to refresh it
        // --> stored for 24 hours.
        // return this.http.get<Card[]>(`${this.baseUri}/cards`)
        return this.http.get<Card[]>(`${this.baseUri}/get`)
            .pipe(
                filter(card => !_.isEmpty(card))
            );
    }

    public createCard(body: any): Observable<Card> {
        // return this.http.get<Card[]>(`${this.baseUri}/cards`)
        return this.http.post<Card>(`${this.baseUri}/post`, body)
            .pipe(
                filter(card => !_.isEmpty(card))
            );
    }

    public updateCard(cardId: number, body: any): Observable<Card> {
        // return this.http.get<Card[]>(`${this.baseUri}/cards`)
        return this.http.put<Card>(`${this.baseUri}/put/dd`, body)
            .pipe(
                filter(card => !_.isEmpty(card))
            );
    }

    public deleteCard(cardId: number): Observable<Card> {
        // return this.http.get<Card[]>(`${this.baseUri}/cards`)
        return this.http.delete<Card>(`${this.baseUri}/delete`)
            .pipe(
                filter(card => !_.isEmpty(card))
            );
    }
}
