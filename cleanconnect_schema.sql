-- SQL Schema for CleanConnect (PostgreSQL Syntax)
-- This schema normalizes the data structure, establishes relationships,
-- and uses appropriate data types for a production environment.

-- Use ENUM types for predefined sets of values to ensure data integrity.
CREATE TYPE user_role AS ENUM ('client', 'cleaner');
CREATE TYPE gender_type AS ENUM ('Male', 'Female', 'Other');
CREATE TYPE entity_type AS ENUM ('Individual', 'Company');
CREATE TYPE subscription_tier AS ENUM ('Free', 'Standard', 'Pro', 'Premium');
CREATE TYPE booking_status AS ENUM ('Upcoming', 'Completed', 'Cancelled');
CREATE TYPE payment_method AS ENUM ('Escrow', 'Direct');
CREATE TYPE payment_status AS ENUM ('Pending Payment', 'Pending Admin Confirmation', 'Confirmed', 'Pending Payout', 'Paid', 'Not Applicable');

-- =================================================================
-- USERS TABLE
-- Stores core information for ALL users (clients, cleaners, admins).
-- Cleaner and Client specific details are in separate profile tables.
-- =================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Store hashed passwords, never plaintext.
    full_name VARCHAR(255) NOT NULL,
    phone_number VARCHAR(50),
    gender gender_type,
    state VARCHAR(100) NOT NULL,
    city VARCHAR(100) NOT NULL,
    other_city VARCHAR(100), -- Used if city is 'Other'
    address TEXT,
    role user_role NOT NULL,
    selfie_url TEXT, -- URL to the file in cloud storage (e.g., S3, GCS)
    government_id_url TEXT, -- URL to the file in cloud storage
    is_admin BOOLEAN DEFAULT false,
    is_suspended BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- =================================================================
-- CLEANER PROFILES TABLE
-- Stores information specific to cleaners.
-- Linked one-to-one with the users table.
-- =================================================================
CREATE TABLE cleaner_profiles (
    user_id UUID PRIMARY KEY,
    cleaner_type entity_type,
    experience_years INT,
    bio TEXT,
    profile_photo_url TEXT,
    nin VARCHAR(11),
    business_reg_doc_url TEXT,
    charge_hourly DECIMAL(10, 2),
    charge_daily DECIMAL(10, 2),
    charge_per_contract DECIMAL(10, 2),
    charge_per_contract_negotiable BOOLEAN DEFAULT false,
    account_number VARCHAR(20),
    bank_name VARCHAR(100),
    subscription_tier subscription_tier DEFAULT 'Free',
    pending_subscription subscription_tier, -- Stores the requested upgrade plan
    subscription_receipt_url TEXT,
    subscription_end_date DATE,
    is_verified BOOLEAN DEFAULT false,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =================================================================
-- CLIENT PROFILES TABLE
-- Stores information specific to clients.
-- =================================================================
CREATE TABLE client_profiles (
    user_id UUID PRIMARY KEY,
    client_type entity_type,
    company_name VARCHAR(255),
    company_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =================================================================
-- BOOKINGS TABLE
-- Central table for all service bookings.
-- =================================================================
CREATE TABLE bookings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL,
    cleaner_id UUID NOT NULL,
    service TEXT NOT NULL,
    booking_date DATE NOT NULL,
    amount DECIMAL(10, 2) NOT NULL, -- Cleaner's charge
    total_amount DECIMAL(10, 2), -- Amount + Escrow fee
    status booking_status DEFAULT 'Upcoming',
    payment_method payment_method NOT NULL,
    payment_status payment_status NOT NULL,
    payment_receipt_url TEXT,
    job_approved_by_client BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now(),
    FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (cleaner_id) REFERENCES users(id) ON DELETE SET NULL
);

-- =================================================================
-- REVIEWS TABLE
-- Stores all reviews, linked to a specific booking.
-- =================================================================
CREATE TABLE reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id UUID UNIQUE NOT NULL, -- Ensures one review per booking
    reviewer_id UUID NOT NULL,
    cleaner_id UUID NOT NULL,
    rating DECIMAL(2, 1) NOT NULL, -- Overall average rating (e.g., 4.7)
    timeliness_rating INT CHECK (timeliness_rating BETWEEN 1 AND 5),
    thoroughness_rating INT CHECK (thoroughness_rating BETWEEN 1 AND 5),
    conduct_rating INT CHECK (conduct_rating BETWEEN 1 AND 5),
    comment TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (cleaner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =================================================================
-- SERVICES LOOKUP TABLE
-- Normalizes cleaning service data.
-- =================================================================
CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

-- =================================================================
-- CLEANER_SERVICES JUNCTION TABLE
-- Manages the many-to-many relationship between cleaners and services.
-- =================================================================
CREATE TABLE cleaner_services (
    cleaner_user_id UUID NOT NULL,
    service_id INT NOT NULL,
    PRIMARY KEY (cleaner_user_id, service_id),
    FOREIGN KEY (cleaner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

-- =================================================================
-- CONTACT MESSAGES TABLE
-- Stores submissions from the "Contact Us" form for admin review.
-- =================================================================
CREATE TABLE contact_messages (
    id SERIAL PRIMARY KEY,
    topic VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- =================================================================
-- INDEXES
-- Add indexes on frequently queried columns to improve performance.
-- =================================================================
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_bookings_client_id ON bookings(client_id);
CREATE INDEX idx_bookings_cleaner_id ON bookings(cleaner_id);
CREATE INDEX idx_reviews_cleaner_id ON reviews(cleaner_id);

-- =================================================================
-- POPULATE SERVICES TABLE (Initial Data)
-- You can run this once to populate the services lookup table.
-- =================================================================
INSERT INTO services (name) VALUES
    ('Residential/Domestic Cleaning'),
    ('Commercial/Office Cleaning'),
    ('Post-Construction'),
    ('Move-In / Move-Out Cleaning'),
    ('Disaster Cleaning & Restoration'),
    ('Carpet and Upholstery Cleaning'),
    ('Glass Cleaning'),
    ('Medical Cleaning'),
    ('Industrial Cleaning'),
    ('Vehicle Cleaning'),
    ('Event Cleaning'),
    ('Outdoor/Environmental Cleaning'),
    ('Hazardous Waste Cleaning'),
    ('Pest control'),
    ('Laundry & ironing'),
    ('Waste Management'),
    ('Deep Cleaning'),
    ('Regular/Routine'),
    ('Spring Cleaning'),
    ('Sanitization/Disinfection'),
    ('Green/Eco-Friendly'),
    ('Crisis/Trauma Cleaning');