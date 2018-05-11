/**
 * Client Class
 */
import { CardsDomain } from './cards';

export class Client {

    public cards: CardsDomain;

    constructor (private baseUri: string) {
        this.cards = new CardsDomain(baseUri);
    }

}
