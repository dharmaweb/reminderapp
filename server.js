require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = process.env.PORT || 3000;

// Initialize Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY,
    {
        auth: {
            autoRefreshToken: true,
            persistSession: true
        }
    }
);

// Initialize Supabase admin client with service role key
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);

// CORS configuration
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000', 'https://your-netlify-app.netlify.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static('.')); // Serve static files from the root directory

// Auth routes
app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password, first_name, last_name } = req.body;
        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: { first_name, last_name },
                emailRedirectTo: `${req.headers.origin}/dashboard.html`
            }
        });

        if (error) throw error;

        if (data.user) {
            await supabase
                .from('user_profiles')
                .insert([{
                    id: data.user.id,
                    first_name,
                    last_name,
                    email_verified: false
                }])
                .select()
                .single();
        }

        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/auth/resend-confirmation', async (req, res) => {
    try {
        const { email, redirect_url } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const { error } = await supabase.auth.resend({
            type: 'signup',
            email,
            options: {
                emailRedirectTo: redirect_url
            }
        });

        if (error) throw error;

        res.json({ message: 'Confirmation email has been resent' });
    } catch (error) {
        console.error('Resend confirmation error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/auth/signin', async (req, res) => {
    try {
        const { email, password } = req.body;
        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/auth/signout', async (req, res) => {
    try {
        const { error } = await supabase.auth.signOut();
        if (error) throw error;
        res.json({ message: 'Signed out successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/auth/reset-password', async (req, res) => {
    try {
        const { email, redirect_url } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: redirect_url
        });

        if (error) throw error;

        res.json({ message: 'Password reset instructions have been sent' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: error.message });
    }
});

// User routes
app.put('/user/profile', async (req, res) => {
    try {
        const { first_name, last_name } = req.body;
        const token = req.headers.authorization?.split('Bearer ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError) throw authError;

        const { data, error } = await supabase.auth.updateUser({
            data: { first_name, last_name }
        });

        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/user/password', async (req, res) => {
    try {
        const { current_password, new_password } = req.body;
        const token = req.headers.authorization?.split('Bearer ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Get the user data
        const { data: { user }, error: userError } = await supabase.auth.getUser(token);
        if (userError) throw userError;

        // First, verify current password by attempting to sign in
        const { error: signInError } = await supabase.auth.signInWithPassword({
            email: user.email,
            password: current_password
        });

        if (signInError) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Set up admin auth client with the service role key
        const { data: updateData, error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
            user.id,
            { password: new_password }
        );

        if (updateError) {
            console.error('Password update error:', updateError);
            throw updateError;
        }

        // Force logout all sessions for this user for security
        const { error: signOutError } = await supabaseAdmin.auth.admin.signOut(user.id);
        if (signOutError) {
            console.error('Sign out error:', signOutError);
            // Don't throw here as password was updated successfully
        }

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Password update error:', error);
        res.status(500).json({ error: error.message || 'Failed to update password' });
    }
});

app.delete('/user', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        const { password } = req.body;
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        // First, get the user data
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError) throw authError;

        // Verify password by attempting to sign in
        const { error: signInError } = await supabase.auth.signInWithPassword({
            email: user.email,
            password
        });

        if (signInError) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Delete user data from user_profiles table first (if you have this table)
        const { error: profileError } = await supabaseAdmin
            .from('user_profiles')
            .delete()
            .eq('id', user.id);

        if (profileError) throw profileError;

        // Delete the user's auth account using admin client
        const { error } = await supabaseAdmin.auth.admin.deleteUser(user.id);
        if (error) throw error;

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/auth/user', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const { data: { user }, error } = await supabase.auth.getUser(token);
        
        if (error) throw error;
        
        res.json(user);
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
}); 
