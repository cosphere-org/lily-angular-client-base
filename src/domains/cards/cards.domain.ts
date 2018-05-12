/**
 * Cards Domain
 */
import { Injectable } from '@angular/core';
import { filter } from 'rxjs/operators';
import { Observable } from 'rxjs';
import * as _ from 'underscore';

import { ClientService, DataState } from '../../services/client.service';
import { Card } from './cards.model';

export interface BulkReadCardsParams {
  limit?: number;
  offset?: number;
  query?: string;
  ids?: number[];
  category_id?: number;
}

@Injectable()
export class CardsDomain {
  constructor(private client: ClientService) {}

  bulkReadCards(params?: BulkReadCardsParams): DataState<Card> {
    return this.client.getDataState<Card>('cards', { params });
  }

  createCard(body: any): Observable<Card> {
    return this.client
      .post<Card>('cadrs', body)
      .pipe(filter(card => !_.isEmpty(card)));
  }

  updateCard(cardId: number, body: any): Observable<Card> {
    return this.client
      .put<Card>(`cards/${cardId}`, body)
      .pipe(filter(card => !_.isEmpty(card)));
  }

  deleteCard(cardId: number): Observable<Card> {
    return this.client
      .delete<Card>(`cards/${cardId}`)
      .pipe(filter(card => !_.isEmpty(card)));
  }
}
