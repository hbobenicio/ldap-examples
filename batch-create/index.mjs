/**
 * PoC :: LDAP :: Batch Loading users (and changing their passwords) in a secure connection.
 * 
 * ## CLI Interface
 * 
 * ```
 * node index.mjs bind "cn=admin,dc=example,dc=org" "adminpassword"
 * node index.mjs batch-load "./fixtures/users.json"
 * node index.mjs reset-all "./fixtures/users.json" "javasucks"
 * node index.mjs reset "cn=batchuser2,dc=example,dc=org" "gorocks"
 * ```
 * 
 * ## Reference Links
 * 
 * - https://stackoverflow.com/questions/4812207/ldap-to-change-user-password
 * - https://www.openldap.org/faq/data/cache/347.html
 * - https://www.digitalocean.com/community/tutorials/how-to-change-account-passwords-on-an-openldap-server
 * - https://datatracker.ietf.org/doc/html/rfc2307
 * - https://github.com/opinsys/node-ssha/blob/master/ssha.js
 * - https://github.com/tonyprawiro/cracking-ldap
 */
import * as crypto from 'node:crypto';
import * as process from 'node:process';
import * as fs from 'node:fs/promises';

import * as ldapts from 'ldapts';

const LDAP_URL = 'ldaps://localhost:1636';
const LDAP_OPERATOR_DN = 'cn=admin,dc=example,dc=org';
const LDAP_OPERATOR_PASSWORD = 'adminpassword';

main()

function main() {
    const args = process.argv.slice(2)
    cmdRoot(args);

    // // You can use ldap:// or ldaps://; the latter would connect over SSL
    // // (note that this will not use the LDAP TLS extended operation,
    // // but literally an SSL connection to port 636, as in LDAP v2)
    // const client = new ldapts.Client({
    //     url: LDAP_URL,
    //     timeout: 5 * 1000,
    //     connectTimeout: 3 * 1000,
    //     tlsOptions: {
    //       minVersion: 'TLSv1.2',
    //       rejectUnauthorized: false,
    //     },
    //     strictDN: true,
    // });

    // // startTLS(options, [controls])
    // // Performs a StartTLS extended operation against the LDAP server to initiate a
    // // TLS-secured communication channel over an otherwise clear-text connection.

    // console.log(`ldap: binding to server... url="${LDAP_URL}"`);
    // try {
    //     // await client.bind('cn=admin,dc=example,dc=org', 'adminpassword');
    //     // console.log('ldap: bind success.');

    //     const userName = 'batchuser1';

    //     // console.log('ldap: adding user...');
    //     // const entry = {
    //     //     cn: 'batchuser1',
    //     //     sn: 'batchuser1',
    //     //     // email: ['foo@bar.com', 'foo1@bar.com'],
    //     //     objectclass: 'inetOrgPerson',
    //     // };
    //     // await client.add('cn=batchuser1,dc=example,dc=org', entry);
    //     // console.log('ldap: user added successfully.');

    //     // console.log(`ldap: changing password... user=${userName}`);
    //     // await client.modify(`cn=${userName},dc=example,dc=org`, new ldapts.Change({
    //     //     operation: 'replace',
    //     //     modification: new ldapts.Attribute({
    //     //         type: 'userPassword',  //;binary
    //     //         values: [ldapPasswordEncode('javasucks')],
    //     //     }),
    //     // }));
    //     // console.log(`ldap: user password changed successfully. user=${userName}`);

    //     await client.bind(`cn=${userName},dc=example,dc=org`, 'javasuckss');
    //     console.log('ldap: bind success.');

    // } finally {
    //     console.log('ldap: unbinding connection...');
    //     await client.unbind();
    //     console.log('ldap: connection unbound.');
    // }
}

/**
 * Root Command of the CLI.
 * 
 * @param {string[]} args Arguments without node and the main script paths
 */
function cmdRoot(args) {
    if (args.length === 0) {
        throw new Error('bad args');
    }

    const cmd = args.shift();
    switch (cmd) {
        case 'batch-load':
            cmdBatchLoad(args);
            break;

        case 'reset-all':
            cmdResetAll(args);
            break;

        case 'reset':
            cmdReset(args);
            break;

        case 'bind':
            cmdBindTest(args);
            break;
    
        default:
            throw new Error('bad args');
    }
}

/**
 * Batch Load CLI Subcommand.
 * 
 * @param {string[]} args The remaining arguments yet to be parsed
 */
function cmdBatchLoad(args) {
    if (args.length === 0) {
        throw new Error('batch-load subcommand: missing fixture argument');
    }

    const fixture = args.shift();
    batchLoad(fixture).catch(console.error);
}

function cmdResetAll(args) {
    if (args.length === 0) throw new Error('reset-all needs 2 arguments: <fixture> <newPassword>');
    const fixture = args.shift();

    if (args.length === 0) throw new Error('reset-all needs 2 arguments: <fixture> <newPassword>');
    const newPassword = args.shift();

    resetAllPassword(fixture, newPassword).catch(console.error);
}

/**
 * Resets the password of all batch users to the same value.
 * 
 * @param {string} fixture 
 * @param {string} newPassword The new password to be set to every batch user
 */
async function resetAllPassword(fixture, newPassword) {
    console.log(`batch loading: starting... fixture="${fixture}"`);
    const fixtureData = await fs.readFile(fixture, { encoding: 'utf-8' });
    const batchUsers = JSON.parse(fixtureData);
    console.log(`fixtures were loaded. usersCount=${batchUsers.length}`);

    const ldapClient = await ldapClientCreate();

    console.log(`ldap: binding to server... url="${LDAP_URL}" userDn="${LDAP_OPERATOR_DN}"`);
    try {
        await ldapClient.bind(LDAP_OPERATOR_DN, LDAP_OPERATOR_PASSWORD);
        console.log('ldap: bind success.');

        console.log('ldap: resetting passwords...');
        const promises = batchUsers.map(batchUser => ldapClient.modify(batchUser.dn, new ldapts.Change({
            operation: 'replace',
            modification: new ldapts.Attribute({
                type: 'userPassword',
                values: [ ldapPasswordEncode(newPassword) ],
            }),
        })));
        //NOTE: batch loading users in parallel. take care with too much parallism! size chunk this for better control
        await Promise.all(promises);

        console.log('ldap: resetting passwords success.');

    } finally {
        console.log('ldap: unbinding connection...');
        await ldapClient.unbind();
        console.log('ldap: connection unbound.');
    }
}

function cmdReset(args) {
    if (args.length == 0) throw new Error('bind needs 2 arguments: <userDn> <password>');
    const userDn = args.shift();

    if (args.length == 0) throw new Error('bind needs 2 arguments: <userDn> <newPassword>');
    const newPassword = args.shift();

    resetPassword(userDn, newPassword).catch(console.error);
}

/**
 * Resets a user's password.
 * 
 * @param {string} userDn User's DN
 * @param {string} newPassword
 */
async function resetPassword(userDn, newPassword) {
    const ldapClient = await ldapClientCreate();

    console.log(`ldap: binding to server... url="${LDAP_URL}" userDn="${LDAP_OPERATOR_DN}"`);
    try {
        await ldapClient.bind(LDAP_OPERATOR_DN, LDAP_OPERATOR_PASSWORD);
        console.log('ldap: bind success.');

        console.log(`ldap: changing password... user=${userDn}`);
        await ldapClient.modify(userDn, new ldapts.Change({
            operation: 'replace',
            modification: new ldapts.Attribute({
                type: 'userPassword',  //;binary
                values: [ ldapPasswordEncode(newPassword) ],
            }),
        }));
        console.log(`ldap: user password changed successfully. user=${userDn}`);

    } finally {
        console.log('ldap: unbinding connection...');
        await ldapClient.unbind();
        console.log('ldap: connection unbound.');
    }
}

function cmdBindTest(args) {
    if (args.length == 0) throw new Error('bind needs 2 arguments: <userDn> <password>');
    const userDn = args.shift();

    if (args.length == 0) throw new Error('bind needs 2 arguments: <userDn> <password>');
    const userPassword = args.shift();

    bindTest(userDn, userPassword).catch(console.error);
}

/**
 * Performs a Bind for testing purposes.
 * 
 * @param {string} userDn User DN (Distinguished Name)
 * @param {string} userPassword  User Password
 */
async function bindTest(userDn, userPassword) {
    const ldapClient = await ldapClientCreate();

    console.log(`ldap: binding to server... url="${LDAP_URL}" userDn="${userDn}"`);
    try {
        await ldapClient.bind(userDn, userPassword);
        console.log('ldap: bind success.');

    } finally {
        console.log('ldap: unbinding connection...');
        await ldapClient.unbind();
        console.log('ldap: connection unbound.');
    }
}

/**
 * Batch loads the specified fixture.
 * 
 * @param {string} fixture The fixture path containing the batch users to be loaded.
 */
async function batchLoad(fixture) {
    console.log(`batch loading: starting... fixture="${fixture}"`);
    const fixtureData = await fs.readFile(fixture, { encoding: 'utf-8' });
    const batchUsers = JSON.parse(fixtureData);
    console.log(`fixtures were loaded. usersCount=${batchUsers.length}`);

    const ldapClient = await ldapClientCreate();

    console.log(`ldap: binding to server... url="${LDAP_URL}" userDn="${LDAP_OPERATOR_DN}"`);
    try {
        await ldapClient.bind(LDAP_OPERATOR_DN, LDAP_OPERATOR_PASSWORD);
        console.log('ldap: bind success.');

        console.log('ldap: adding users...');

        //NOTE: batch loading users in parallel. take care with too much parallism! size chunk this for better control
        const promises = batchUsers.map(batchUser => ldapClient.add(batchUser.dn, batchUser.entry));
        await Promise.all(promises);

        console.log('ldap: adding users success.');

    } finally {
        console.log('ldap: unbinding connection...');
        await ldapClient.unbind();
        console.log('ldap: connection unbound.');
    }
}

/**
 * Creates a new LDAP Client.
 * 
 * @returns {ldapts.Client} The client instance
 */
async function ldapClientCreate() {
    return new ldapts.Client({
        url: LDAP_URL,
        timeout: 3 * 1000,
        connectTimeout: 2 * 1000,
        tlsOptions: {
            minVersion: 'TLSv1.2',
            rejectUnauthorized: true,

            //TODO this ca file can be loaded in background only once
            ca: await fs.readFile('./tls/ca-fullchain.pem'),
        },
        strictDN: true,
    });
}

/**
 * Encodes a password using SSHA, which is basically `'{SSHA}' + base64(SHA1(clear_text + salt) + salt)`.
 * 
 * NOTE(security): SSHA is an insecure and broken hashing algorithm.
 *                 Never expose these values (they could be decoded with brute force/rainbow tables).
 *                 Check your LDAP Server if it provide better algorithms.
 * 
 * @param {string} password The clear text password
 * @returns {string} the LDAP {SSHA} encoded password
 * 
 * @see https://github.com/opinsys/node-ssha/blob/master/ssha.js
 * @see https://datatracker.ietf.org/doc/html/rfc2307
 * @see https://github.com/tonyprawiro/cracking-ldap
 */
function ldapPasswordEncode(password) {
    const sha1 = crypto.createHash('sha1');
    const salt = crypto.randomBytes(32);
    sha1.update(Buffer.from(password));
    sha1.update(salt);
    const digest = sha1.digest();
    return '{SSHA}' + Buffer.concat([digest, salt]).toString('base64');
}
