/**
 * Facade service for all domains
 */
import { Injectable, Injector } from '@angular/core';
import { Observable } from 'rxjs';

import { DataState, Options } from './index';

import { CardsDomain, Card, BulkReadCardsParams } from '../domains/cards/index';

@Injectable()
export class CoSphereService {
  /**
   * Inject Cards domain
   */
  private _cardsDomain: CardsDomain;
  public get cardsDomain(): CardsDomain {
    if (!this._cardsDomain) {
      this._cardsDomain = this.injector.get(CardsDomain);
    }
    return this._cardsDomain;
  }

  constructor(private injector: Injector) {}

  /**
   * Cards domain methods
   */
  bulkReadCards(params: BulkReadCardsParams): DataState<Card> {
    return this.cardsDomain.bulkReadCards(params);
  }

  createCard(body: any): Observable<Card> {
    return this.cardsDomain.createCard(body);
  }

  updateCard(cardId: number, body: any): Observable<Card> {
    return this.cardsDomain.updateCard(cardId, body);
  }

  deleteCard(cardId: number): Observable<Card> {
    return this.cardsDomain.deleteCard(cardId);
  }
}
