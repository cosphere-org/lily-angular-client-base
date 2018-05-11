/**
 * Card Domain Examples
 */
import { Client as APIClient } from '@cosphere/Client';


const client = new APIClient('https://httpbin.org');
// const client = new APIClient('https://api.cosphere.org');
// const client = new APIClient('https://staging-api.cosphere.org');


// const client = new Client('https://localhost');


client.cards.bulkReadCards().subscribe((response) => {
    console.log('=====> BULK READ');
    console.log(response);
});

client.cards.createCard({what: 'ever'}).subscribe((response) => {
    console.log('=====> CREATE');
    console.log(response);
});

client.cards.updateCard(11, {what: 'ever'}).subscribe((response) => {
    console.log('=====> UPDATE');
    console.log(response);
});

client.cards.deleteCard(11).subscribe((response) => {
    console.log('=====> DELETE');
    console.log(response);
});
