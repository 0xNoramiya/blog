import React, { useState } from 'react';
import { Button } from '@/components/ui/button';

interface ProtectedPostProps {
    ciphertext: string;
    iv: string;
    salt: string;
}

export default function ProtectedPost({ ciphertext, iv, salt }: ProtectedPostProps) {
    const [password, setPassword] = useState('');
    const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
    const [error, setError] = useState(false);
    const [loading, setLoading] = useState(false);

    const handleDecrypt = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(false);

        try {
            const enc = new TextEncoder();
            const dec = new TextDecoder();

            // 1. Import Key material from password
            const keyMaterial = await window.crypto.subtle.importKey(
                "raw",
                enc.encode(password),
                { name: "PBKDF2" },
                false,
                ["deriveKey"]
            );

            // 2. Derive Key using PBKDF2 and the provided salt
            // Note: Salt must be converted from hex/base64 to buffer. Assuming hex string input.
            const saltBuffer = Uint8Array.from(salt.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));

            const key = await window.crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: saltBuffer,
                    iterations: 100000,
                    hash: "SHA-256"
                },
                keyMaterial,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );

            // 3. Decrypt
            // IV also hex string
            const ivBuffer = Uint8Array.from(iv.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
            // Ciphertext hex string
            const ctBuffer = Uint8Array.from(ciphertext.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));

            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: ivBuffer
                },
                key,
                ctBuffer
            );

            setDecryptedContent(dec.decode(decrypted));
        } catch (err) {
            console.error(err);
            setError(true);
        } finally {
            setLoading(false);
        }
    };

    if (decryptedContent) {
        return (
            <div
                className="prose dark:prose-invert max-w-none"
                dangerouslySetInnerHTML={{ __html: decryptedContent }}
            />
        );
    }

    return (
        <div className="flex flex-col items-center justify-center p-8 border rounded-lg bg-card text-card-foreground shadow-sm max-w-md mx-auto mt-8">
            <div className="text-center space-y-2 mb-6">
                <h3 className="text-2xl font-semibold leading-none tracking-tight">Protected Content</h3>
                <p className="text-sm text-muted-foreground">
                    This writeup is password protected. Please enter the password to view.
                </p>
            </div>

            <form onSubmit={handleDecrypt} className="w-full space-y-4">
                <div className="space-y-2">
                    <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter password"
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                        required
                    />
                </div>

                {error && (
                    <div className="text-sm font-medium text-destructive text-center">
                        Incorrect password or decryption failed.
                    </div>
                )}

                <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? 'Decrypting...' : 'Unlock'}
                </Button>
            </form>
            <div className="mt-4 text-xs text-muted-foreground">
                Hint: "hacking"
            </div>
        </div>
    );
}
