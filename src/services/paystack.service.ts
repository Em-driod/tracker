import { config } from '../config';

const PAYSTACK_API_URL = 'https://api.paystack.co';

export const initializeTransaction = async (email: string, amount: number) => {
    const response = await fetch(`${PAYSTACK_API_URL}/transaction/initialize`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${config.paystack.secretKey}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email,
            amount: amount * 100, // Paystack amount is in kobo (NGN) or cents
            callback_url: `${config.webauthn.origin}/dashboard/wallet`, // Fallback to origin
        }),
    });

    const data = await response.json();
    if (!data.status) {
        throw new Error(data.message || 'Paystack initialization failed');
    }

    return data.data; // { authorization_url, access_code, reference }
};

export const verifyTransaction = async (reference: string) => {
    const response = await fetch(`${PAYSTACK_API_URL}/transaction/verify/${reference}`, {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${config.paystack.secretKey}`,
        },
    });

    const data = await response.json();
    if (!data.status) {
        throw new Error(data.message || 'Paystack verification failed');
    }

    return data.data; // Includes amount, status, metadata, etc.
};
