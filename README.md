
# cosphere-angular-client

Domain Oriented Client for communication between Backend and Frontend of CoSphere.

Here is the example of the possible Mock usage?

```TypeScript

import { ReadCardsCases } from '...';


class superService {

    superMethod () {
        this.client.cards.readCards().COS...;

        this.client.cards.readCards.returns(c: ReadCardsCases => [
            c.200_as_learner
        ]).COS...;

    }
}

```