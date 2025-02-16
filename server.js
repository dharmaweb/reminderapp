require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = process.env.PORT || 3000;

// Initialize Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
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
        const { password } = req.body;
        const token = req.headers.authorization?.split('Bearer ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const { error } = await supabase.auth.updateUser({
            password
        });

        if (error) throw error;
        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/user', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError) throw authError;

        const { error } = await supabase.auth.admin.deleteUser(user.id);
        if (error) throw error;

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
}); 