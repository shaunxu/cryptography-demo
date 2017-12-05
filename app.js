'use strict';

const crypto = require('crypto');
const fs = require('fs');

const _ = require('lodash');
const ursa = require('ursa');

const demo1 = function () {

	const encrypt = function (text) {
		return _.map(text, x => x.charCodeAt(0)).join(`|`);
	};

	const decrypt = function (cipher) {
		return _.map(cipher.split(`|`), x => String.fromCharCode(Number(x))).join(``);
	};

	const text = `hello world`;
	const cipher = encrypt(text);
	const result = decrypt(cipher);

	console.log(JSON.stringify({
		text: text,
		cipher: cipher,
		result: result
	}, null, 2));

};


const demo2 = function () {

	const encrypt = function (text, key) {
		return _.map(text, x => x.charCodeAt(0) + key).join(`|`);
	};

	const decrypt = function (cipher, key) {
		return _.map(cipher.split(`|`), x => String.fromCharCode(Number(x - key))).join(``);
	};

	const text = `hello world`;
	const cipher = encrypt(text, 1);
	const result = decrypt(cipher, 1);

	console.log(JSON.stringify({
		text: text,
		cipher: cipher,
		result: result
	}, null, 2));

};

const demo3 = function () {

	const encrypt = function (text, key, iv) {
		const encrypter = crypto.createCipheriv(`des`, key, iv || Buffer.alloc(8, 0));
		let cipher = encrypter.update(text, `utf8`, `base64`);
		cipher += encrypter.final(`base64`);
		return cipher;
	};

	const decrypt = function (cipher, key, iv) {
		const decrypter = crypto.createDecipheriv(`des`, key, iv || Buffer.alloc(8, 0));
		let result = decrypter.update(cipher, `base64`, `utf8`);
		result += decrypter.final(`utf8`);
		return result;
	};

	const text = `hello world`;
	const cipher = encrypt(text, `shaun xu`);
	const result = decrypt(cipher, `shaun xu`);

	console.log(JSON.stringify({
		text: text,
		cipher: cipher,
		result: result
	}, null, 2));

};

const demo4 = function () {
	
	const encrypt = function (text, key, iv) {
		const encrypter = crypto.createCipheriv(`aes-256-cbc`, crypto.createHash(`sha256`).update(key, `utf8`).digest(), iv || Buffer.alloc(16, 0));
		let cipher = encrypter.update(text, `utf8`, `base64`);
		cipher += encrypter.final(`base64`);
		return cipher;
	};

	const decrypt = function (cipher, key, iv) {
		const decrypter = crypto.createDecipheriv(`aes-256-cbc`, crypto.createHash(`sha256`).update(key, `utf8`).digest(), iv || Buffer.alloc(16, 0));
		let result = decrypter.update(cipher, `base64`, `utf8`);
		result += decrypter.final(`utf8`);
		return result;
	};

	const text = `hello world`;
	const cipher = encrypt(text, `i love worktile`);
	const result = decrypt(cipher, `i love worktile`);

	console.log(JSON.stringify({
		text: text,
		cipher: cipher,
		result: result
	}, null, 2));

};

const demo5 = function () {
	
	const p = 3;
	const q = 11;
	const N = p * q;
	const r = (p - 1) * (q - 1);

	let e = 3;
	let d;
	let k;

	for (let __d = 1; __d < r; __d++) {
		const ed = e * __d;
		const ed_mod_r = ed % r;
		const one_mod_r = 1 % r;
		if (ed_mod_r === one_mod_r) {
			d = __d;
			break;
		}
	}

	console.log(JSON.stringify({
		p: p,
		q: q,
		N: N,
		r: r,
		e: e,
		d: d,
		k: k,
		key_binary: N.toString(2),
		key_length: N.toString(2).length
	}, null, 2));

	if (d) {
		const key = {
			public: {
				N: N,
				e: e
			},
			private: {
				N: N,
				d: d
			}
		};
	
		console.log(JSON.stringify(key, null, 2));
	
		const data = 13;
		const cipher = (data ** key.public.e) % N;
		const result = (cipher ** key.private.d) % N;
		console.log(JSON.stringify({
			data: data,
			cipher: cipher,
			result: result
		}, null, 2));
	}
	else {
		console.log(`bad`);
	}

};

const demo6 = function () {

	const keys = ursa.generatePrivateKey();
	const pems = {
		public: keys.toPublicPem(`base64`),
		private: keys.toPrivatePem(`base64`)
	};

	const encrypt = function (text, key) {
		const cipher = crypto.publicEncrypt(Buffer.from(key, `base64`), Buffer.from(text, `utf8`));
		return cipher.toString(`base64`);
	};

	const decrypt = function (cipher, key) {
		const result = crypto.privateDecrypt(Buffer.from(key, `base64`), Buffer.from(cipher, `base64`));
		return result.toString(`utf8`);
	};

	const text = `hello world`;
	const cipher = encrypt(text, pems.public);
	const result = decrypt(cipher, pems.private);

	console.log(JSON.stringify({
		text: text,
		cipher: cipher,
		result: result
	}, null, 2));

};

const demo7 = function () {

	const sign = function (privateKeyPath, profilePath) {
		const private_key = fs.readFileSync(privateKeyPath, `utf8`);	
		const profile = fs.readFileSync(profilePath, `utf8`);
		const sign = crypto.createSign(`RSA-SHA256`);
		sign.update(profile);
		const license = sign.sign(private_key, `base64`);
		return license;
	};

	const verify = function (publicKeyPath, profilePath, license) {
		const public_key = fs.readFileSync(publicKeyPath, `utf8`);
		const profile = fs.readFileSync(profilePath, `utf8`);
		const verifier = crypto.createVerify(`RSA-SHA256`);
		verifier.update(profile);
		const result = verifier.verify(public_key, Buffer.from(license, `base64`));
		return result;
	};

	const public_key_path = `./demo_pub.pem`;
	const private_key_path = `./demo_pri.pem`;
	const profile_path = `./demo.profile`;
	const profile_path_tampered = `./demo.profile.tampered`;

	const license = sign(private_key_path, profile_path);
	console.log(`LICENSE: \n${license}\n`);

	const result = verify(public_key_path, profile_path, license);
	if (result) {
		console.log(`PASS`);
	}
	else {
		console.log(`FAILED.`);
	}

};

const demo8 = function () {
	console.log(JSON.stringify(crypto.getHashes(), null, 2));
};

demo5();