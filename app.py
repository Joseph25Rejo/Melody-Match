import os
import jwt
import requests
import spotipy
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
from spotipy.oauth2 import SpotifyOAuth
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import logging

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-this')

# Enable CORS for Next.js frontend
CORS(app, origins=['http://localhost:3000'], supports_credentials=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
SPOTIFY_CLIENT_ID = os.getenv('SPOTIFY_CLIENT_ID')
SPOTIFY_CLIENT_SECRET = os.getenv('SPOTIFY_CLIENT_SECRET')
SPOTIFY_REDIRECT_URI = os.getenv('SPOTIFY_REDIRECT_URI', 'http://127.0.0.1:5000/callback')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-this')

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client.music_dating_app
users_collection = db.users
music_data_collection = db.music_data
matches_collection = db.matches

# Spotify OAuth setup
spotify_oauth = SpotifyOAuth(
    client_id=SPOTIFY_CLIENT_ID,
    client_secret=SPOTIFY_CLIENT_SECRET,
    redirect_uri=SPOTIFY_REDIRECT_URI,
    scope="user-read-private user-read-email user-top-read playlist-modify-public playlist-modify-private user-library-read"
)

# JWT token validation decorator
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user_id, *args, **kwargs)
    return decorated_function

# Helper function to generate personality vector from audio features
def generate_personality_vector(audio_features_list):
    """
    Generate a personality vector based on audio features of user's top tracks
    Uses: danceability, energy, valence, acousticness, instrumentalness, speechiness
    """
    if not audio_features_list:
        return [0.5] * 6  # Default neutral vector
    
    features = []
    for track_features in audio_features_list:
        if track_features:
            features.append([
                track_features.get('danceability', 0.5),
                track_features.get('energy', 0.5),
                track_features.get('valence', 0.5),
                track_features.get('acousticness', 0.5),
                track_features.get('instrumentalness', 0.5),
                track_features.get('speechiness', 0.5)
            ])
    
    if not features:
        return [0.5] * 6
    
    # Average the features across all tracks
    return np.mean(features, axis=0).tolist()

# Helper function to calculate compatibility score
def calculate_compatibility_score(vector1, vector2):
    """Calculate compatibility score using cosine similarity"""
    try:
        similarity = cosine_similarity([vector1], [vector2])[0][0]
        # Convert to percentage (0-100)
        return max(0, min(100, int((similarity + 1) * 50)))
    except:
        return 50  # Default score if calculation fails

# Authentication Routes

@app.route('/signup', methods=['GET'])
def signup():
    """Initiate Spotify OAuth for signup"""
    try:
        auth_url = spotify_oauth.get_authorize_url()
        return jsonify({'auth_url': auth_url})
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'error': 'Failed to initiate signup'}), 500

@app.route('/login', methods=['GET'])
def login():
    """Initiate Spotify OAuth for login (same as signup)"""
    try:
        auth_url = spotify_oauth.get_authorize_url()
        return jsonify({'auth_url': auth_url})
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Failed to initiate login'}), 500

@app.route('/callback', methods=['GET'])
def callback():
    """Handle Spotify OAuth callback"""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({'error': 'Authorization code not provided'}), 400
        
        # Get access token
        token_info = spotify_oauth.get_access_token(code)
        access_token = token_info['access_token']
        
        # Initialize Spotify client
        sp = spotipy.Spotify(auth=access_token)
        
        # Get user profile
        spotify_user = sp.current_user()
        spotify_id = spotify_user['id']
        email = spotify_user.get('email')
        display_name = spotify_user.get('display_name', spotify_id)
        
        # Check if user exists
        existing_user = users_collection.find_one({'spotify_id': spotify_id})
        
        if existing_user:
            user_id = str(existing_user['_id'])
        else:
            # Create new user
            # Get user's top tracks for personality vector
            top_tracks = sp.current_user_top_tracks(limit=50, time_range='medium_term')
            track_ids = [track['id'] for track in top_tracks['items']]
            
            # Get audio features
            audio_features = sp.audio_features(track_ids) if track_ids else []
            personality_vector = generate_personality_vector(audio_features)
            
            # Create user document
            user_doc = {
                'spotify_id': spotify_id,
                'email': email,
                'username': display_name,
                'profile_image': spotify_user.get('images', [{}])[0].get('url') if spotify_user.get('images') else None,
                'personality_vector': personality_vector,
                'created_at': datetime.utcnow(),
                'spotify_access_token': access_token,
                'spotify_refresh_token': token_info.get('refresh_token'),
                'profile_info': {
                    'bio': '',
                    'age': None,
                    'location': '',
                    'interests': []
                }
            }
            
            result = users_collection.insert_one(user_doc)
            user_id = str(result.inserted_id)
            
            # Store initial music data
            store_user_music_data(user_id, sp)
        
        # Generate JWT token
        jwt_payload = {
            'user_id': user_id,
            'spotify_id': spotify_id,
            'exp': datetime.utcnow() + timedelta(days=30)
        }
        jwt_token = jwt.encode(jwt_payload, JWT_SECRET_KEY, algorithm='HS256')
        
        return jsonify({
            'token': jwt_token,
            'user_id': user_id,
            'message': 'Authentication successful'
        })
        
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

# User Profile Routes

@app.route('/user/<user_id>', methods=['GET'])
@token_required
def get_user_profile(current_user_id, user_id):
    """Get user profile (partial or full based on unlock status)"""
    try:
        # Check if requesting own profile
        if current_user_id == user_id:
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Return full profile for own user
            profile = {
                'user_id': str(user['_id']),
                'username': user['username'],
                'profile_image': user.get('profile_image'),
                'bio': user['profile_info'].get('bio', ''),
                'age': user['profile_info'].get('age'),
                'location': user['profile_info'].get('location', ''),
                'interests': user['profile_info'].get('interests', [])
            }
            return jsonify(profile)
        
        # Check unlock status for other users
        match = matches_collection.find_one({
            '$or': [
                {'user1_id': current_user_id, 'user2_id': user_id},
                {'user1_id': user_id, 'user2_id': current_user_id}
            ]
        })
        
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Determine what info to reveal
        if match and match.get('unlocked', False):
            # Full profile
            profile = {
                'user_id': str(user['_id']),
                'username': user['username'],
                'profile_image': user.get('profile_image'),
                'bio': user['profile_info'].get('bio', ''),
                'age': user['profile_info'].get('age'),
                'location': user['profile_info'].get('location', ''),
                'interests': user['profile_info'].get('interests', []),
                'unlocked': True
            }
        else:
            # Partial profile
            profile = {
                'user_id': str(user['_id']),
                'username': user['username'],
                'profile_image': user.get('profile_image'),
                'unlocked': False
            }
        
        return jsonify(profile)
        
    except Exception as e:
        logger.error(f"Get user profile error: {str(e)}")
        return jsonify({'error': 'Failed to fetch user profile'}), 500

@app.route('/user/<user_id>', methods=['PUT'])
@token_required
def update_user_profile(current_user_id, user_id):
    """Update user profile (only own profile)"""
    try:
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        update_fields = {}
        
        # Update allowed profile fields
        if 'bio' in data:
            update_fields['profile_info.bio'] = data['bio']
        if 'age' in data:
            update_fields['profile_info.age'] = data['age']
        if 'location' in data:
            update_fields['profile_info.location'] = data['location']
        if 'interests' in data:
            update_fields['profile_info.interests'] = data['interests']
        
        if update_fields:
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': update_fields}
            )
        
        return jsonify({'message': 'Profile updated successfully'})
        
    except Exception as e:
        logger.error(f"Update user profile error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500

# Music Data Routes

async def store_user_music_data(user_id, spotify_client):
    """Store user's music data from Spotify"""
    try:
        # Get top tracks
        top_tracks = spotify_client.current_user_top_tracks(limit=50, time_range='medium_term')
        
        # Get top artists
        top_artists = spotify_client.current_user_top_artists(limit=50, time_range='medium_term')
        
        # Get audio features for top tracks
        track_ids = [track['id'] for track in top_tracks['items']]
        audio_features = spotify_client.audio_features(track_ids) if track_ids else []
        
        # Store music data
        music_doc = {
            'user_id': user_id,
            'top_tracks': top_tracks['items'],
            'top_artists': top_artists['items'],
            'audio_features': audio_features,
            'last_updated': datetime.utcnow()
        }
        
        # Upsert music data
        music_data_collection.update_one(
            {'user_id': user_id},
            {'$set': music_doc},
            upsert=True
        )
        
    except Exception as e:
        logger.error(f"Store music data error: {str(e)}")

@app.route('/user/<user_id>/music', methods=['GET'])
@token_required
def get_user_music(current_user_id, user_id):
    """Get user's music data"""
    try:
        music_data = music_data_collection.find_one({'user_id': user_id})
        
        if not music_data:
            return jsonify({'error': 'Music data not found'}), 404
        
        # Remove MongoDB ObjectId for JSON serialization
        music_data.pop('_id', None)
        
        return jsonify(music_data)
        
    except Exception as e:
        logger.error(f"Get user music error: {str(e)}")
        return jsonify({'error': 'Failed to fetch music data'}), 500

@app.route('/user/<user_id>/music', methods=['PUT'])
@token_required
def update_user_music(current_user_id, user_id):
    """Update user's music data from Spotify"""
    try:
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get user's Spotify token
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Initialize Spotify client
        sp = spotipy.Spotify(auth=user['spotify_access_token'])
        
        # Update music data
        store_user_music_data(user_id, sp)
        
        # Update personality vector
        music_data = music_data_collection.find_one({'user_id': user_id})
        if music_data and music_data.get('audio_features'):
            personality_vector = generate_personality_vector(music_data['audio_features'])
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'personality_vector': personality_vector}}
            )
        
        return jsonify({'message': 'Music data updated successfully'})
        
    except Exception as e:
        logger.error(f"Update user music error: {str(e)}")
        return jsonify({'error': 'Failed to update music data'}), 500

# Matching Routes

@app.route('/matches/<user_id>', methods=['GET'])
@token_required
def get_potential_matches(current_user_id, user_id):
    """Get potential matches for user based on music compatibility"""
    try:
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get current user
        current_user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        current_vector = current_user.get('personality_vector', [0.5] * 6)
        
        # Get existing matches to exclude
        existing_matches = matches_collection.find({
            '$or': [
                {'user1_id': user_id},
                {'user2_id': user_id}
            ]
        })
        
        matched_user_ids = set()
        for match in existing_matches:
            matched_user_ids.add(match['user1_id'])
            matched_user_ids.add(match['user2_id'])
        matched_user_ids.discard(user_id)  # Remove self
        
        # Find potential matches (exclude self and existing matches)
        potential_users = users_collection.find({
            '_id': {'$nin': [ObjectId(uid) for uid in matched_user_ids] + [ObjectId(user_id)]},
            'personality_vector': {'$exists': True}
        })
        
        matches = []
        for user in potential_users:
            other_vector = user.get('personality_vector', [0.5] * 6)
            compatibility_score = calculate_compatibility_score(current_vector, other_vector)
            
            matches.append({
                'user_id': str(user['_id']),
                'username': user['username'],
                'profile_image': user.get('profile_image'),
                'compatibility_score': compatibility_score
            })
        
        # Sort by compatibility score (highest first)
        matches.sort(key=lambda x: x['compatibility_score'], reverse=True)
        
        # Return top 10 matches
        return jsonify({'matches': matches[:10]})
        
    except Exception as e:
        logger.error(f"Get potential matches error: {str(e)}")
        return jsonify({'error': 'Failed to fetch matches'}), 500

@app.route('/matches/<match_id>/first-song', methods=['POST'])
@token_required
def send_first_song(current_user_id, match_id):
    """Send first song to initiate contact with a match"""
    try:
        data = request.get_json()
        other_user_id = data.get('other_user_id')
        song_id = data.get('song_id')
        message = data.get('message', '')
        
        if not other_user_id or not song_id:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if match already exists
        existing_match = matches_collection.find_one({
            '$or': [
                {'user1_id': current_user_id, 'user2_id': other_user_id},
                {'user1_id': other_user_id, 'user2_id': current_user_id}
            ]
        })
        
        if existing_match:
            return jsonify({'error': 'Match already exists'}), 409
        
        # Calculate compatibility score
        user1 = users_collection.find_one({'_id': ObjectId(current_user_id)})
        user2 = users_collection.find_one({'_id': ObjectId(other_user_id)})
        
        if not user1 or not user2:
            return jsonify({'error': 'User not found'}), 404
        
        vector1 = user1.get('personality_vector', [0.5] * 6)
        vector2 = user2.get('personality_vector', [0.5] * 6)
        compatibility_score = calculate_compatibility_score(vector1, vector2)
        
        # Create match
        match_doc = {
            'user1_id': current_user_id,
            'user2_id': other_user_id,
            'match_score': compatibility_score,
            'shared_playlist_id': None,
            'interaction_count': 1,
            'unlocked': False,
            'created_at': datetime.utcnow(),
            'first_song': {
                'song_id': song_id,
                'message': message,
                'sent_by': current_user_id
            }
        }
        
        result = matches_collection.insert_one(match_doc)
        
        return jsonify({
            'match_id': str(result.inserted_id),
            'message': 'First song sent successfully'
        })
        
    except Exception as e:
        logger.error(f"Send first song error: {str(e)}")
        return jsonify({'error': 'Failed to send first song'}), 500

# Playlist Management Routes

@app.route('/matches/<match_id>/playlist', methods=['GET'])
@token_required
def get_shared_playlist(current_user_id, match_id):
    """Get shared playlist for a match"""
    try:
        match = matches_collection.find_one({'_id': ObjectId(match_id)})
        if not match:
            return jsonify({'error': 'Match not found'}), 404
        
        # Verify user is part of this match
        if current_user_id not in [match['user1_id'], match['user2_id']]:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get user's Spotify token
        user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        sp = spotipy.Spotify(auth=user['spotify_access_token'])
        
        playlist_id = match.get('shared_playlist_id')
        
        if not playlist_id:
            # Create shared playlist if it doesn't exist
            other_user_id = match['user2_id'] if match['user1_id'] == current_user_id else match['user1_id']
            other_user = users_collection.find_one({'_id': ObjectId(other_user_id)})
            
            playlist_name = f"{user['username']} ❤️ {other_user['username']}"
            playlist = sp.user_playlist_create(
                user['spotify_id'],
                playlist_name,
                public=False,
                description="Shared playlist from our music dating app connection"
            )
            
            playlist_id = playlist['id']
            matches_collection.update_one(
                {'_id': ObjectId(match_id)},
                {'$set': {'shared_playlist_id': playlist_id}}
            )
        
        # Get playlist tracks
        playlist_tracks = sp.playlist_tracks(playlist_id)
        
        return jsonify({
            'playlist_id': playlist_id,
            'tracks': playlist_tracks['items']
        })
        
    except Exception as e:
        logger.error(f"Get shared playlist error: {str(e)}")
        return jsonify({'error': 'Failed to fetch shared playlist'}), 500

@app.route('/matches/<match_id>/playlist', methods=['POST'])
@token_required
def add_to_shared_playlist(current_user_id, match_id):
    """Add song to shared playlist"""
    try:
        data = request.get_json()
        track_id = data.get('track_id')
        
        if not track_id:
            return jsonify({'error': 'Track ID is required'}), 400
        
        match = matches_collection.find_one({'_id': ObjectId(match_id)})
        if not match:
            return jsonify({'error': 'Match not found'}), 404
        
        # Verify user is part of this match
        if current_user_id not in [match['user1_id'], match['user2_id']]:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get user's Spotify token
        user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        sp = spotipy.Spotify(auth=user['spotify_access_token'])
        
        playlist_id = match.get('shared_playlist_id')
        if not playlist_id:
            return jsonify({'error': 'Shared playlist not found'}), 404
        
        # Add track to playlist
        sp.playlist_add_items(playlist_id, [f"spotify:track:{track_id}"])
        
        # Increment interaction count
        matches_collection.update_one(
            {'_id': ObjectId(match_id)},
            {'$inc': {'interaction_count': 1}}
        )
        
        return jsonify({'message': 'Song added to shared playlist'})
        
    except Exception as e:
        logger.error(f"Add to shared playlist error: {str(e)}")
        return jsonify({'error': 'Failed to add song to playlist'}), 500

# Match Scoring and Interaction Routes

@app.route('/matches/<match_id>/score', methods=['GET'])
@token_required
def get_compatibility_score(current_user_id, match_id):
    """Get compatibility score for a match"""
    try:
        match = matches_collection.find_one({'_id': ObjectId(match_id)})
        if not match:
            return jsonify({'error': 'Match not found'}), 404
        
        # Verify user is part of this match
        if current_user_id not in [match['user1_id'], match['user2_id']]:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify({
            'match_score': match['match_score'],
            'interaction_count': match['interaction_count']
        })
        
    except Exception as e:
        logger.error(f"Get compatibility score error: {str(e)}")
        return jsonify({'error': 'Failed to fetch compatibility score'}), 500

@app.route('/matches/<match_id>/interact', methods=['POST'])
@token_required
def track_interaction(current_user_id, match_id):
    """Track interaction between matched users"""
    try:
        data = request.get_json()
        interaction_type = data.get('type', 'general')  # message, like, playlist_add, etc.
        
        match = matches_collection.find_one({'_id': ObjectId(match_id)})
        if not match:
            return jsonify({'error': 'Match not found'}), 404
        
        # Verify user is part of this match
        if current_user_id not in [match['user1_id'], match['user2_id']]:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Increment interaction count
        result = matches_collection.update_one(
            {'_id': ObjectId(match_id)},
            {
                '$inc': {'interaction_count': 1},
                '$set': {'last_interaction': datetime.utcnow()}
            }
        )
        
        # Get updated interaction count
        updated_match = matches_collection.find_one({'_id': ObjectId(match_id)})
        interaction_count = updated_match['interaction_count']
        
        return jsonify({
            'message': 'Interaction tracked',
            'interaction_count': interaction_count,
            'can_unlock': interaction_count >= 10  # Threshold for unlocking
        })
        
    except Exception as e:
        logger.error(f"Track interaction error: {str(e)}")
        return jsonify({'error': 'Failed to track interaction'}), 500

@app.route('/matches/<match_id>/unlock', methods=['POST'])
@token_required
def unlock_match_profile(current_user_id, match_id):
    """Unlock full profile info when interaction threshold is met"""
    try:
        match = matches_collection.find_one({'_id': ObjectId(match_id)})
        if not match:
            return jsonify({'error': 'Match not found'}), 404
        
        # Verify user is part of this match
        if current_user_id not in [match['user1_id'], match['user2_id']]:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check if already unlocked
        if match.get('unlocked', False):
            return jsonify({'message': 'Profile already unlocked'})
        
        # Check interaction threshold (10 interactions required)
        if match['interaction_count'] < 10:
            return jsonify({
                'error': 'Insufficient interactions to unlock profile',
                'required': 10,
                'current': match['interaction_count']
            }), 400
        
        # Unlock the match
        matches_collection.update_one(
            {'_id': ObjectId(match_id)},
            {
                '$set': {
                    'unlocked': True,
                    'unlocked_at': datetime.utcnow()
                }
            }
        )
        
        return jsonify({'message': 'Profile unlocked successfully'})
        
    except Exception as e:
        logger.error(f"Unlock match profile error: {str(e)}")
        return jsonify({'error': 'Failed to unlock profile'}), 500

# Additional Utility Routes

@app.route('/user/<user_id>/matches', methods=['GET'])
@token_required
def get_user_matches(current_user_id, user_id):
    """Get all matches for a user"""
    try:
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        matches = matches_collection.find({
            '$or': [
                {'user1_id': user_id},
                {'user2_id': user_id}
            ]
        }).sort('last_interaction', -1)
        
        match_list = []
        for match in matches:
            other_user_id = match['user2_id'] if match['user1_id'] == user_id else match['user1_id']
            other_user = users_collection.find_one({'_id': ObjectId(other_user_id)})
            
            if other_user:
                match_info = {
                    'match_id': str(match['_id']),
                    'other_user': {
                        'user_id': str(other_user['_id']),
                        'username': other_user['username'],
                        'profile_image': other_user.get('profile_image')
                    },
                    'match_score': match['match_score'],
                    'interaction_count': match['interaction_count'],
                    'unlocked': match.get('unlocked', False),
                    'created_at': match['created_at'].isoformat(),
                    'last_interaction': match.get('last_interaction', match['created_at']).isoformat()
                }
                match_list.append(match_info)
        
        return jsonify({'matches': match_list})
        
    except Exception as e:
        logger.error(f"Get user matches error: {str(e)}")
        return jsonify({'error': 'Failed to fetch user matches'}), 500

@app.route('/search/tracks', methods=['GET'])
@token_required
def search_tracks(current_user_id):
    """Search for tracks using Spotify API"""
    try:
        query = request.args.get('q')
        limit = int(request.args.get('limit', 20))
        
        if not query:
            return jsonify({'error': 'Query parameter is required'}), 400
        
        # Get user's Spotify token
        user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        sp = spotipy.Spotify(auth=user['spotify_access_token'])
        
        # Search for tracks
        results = sp.search(q=query, type='track', limit=limit)
        
        return jsonify({
            'tracks': results['tracks']['items']
        })
        
    except Exception as e:
        logger.error(f"Search tracks error: {str(e)}")
        return jsonify({'error': 'Failed to search tracks'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test MongoDB connection
        db.command('ping')
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'services': {
                'mongodb': 'connected',
                'spotify': 'configured' if SPOTIFY_CLIENT_ID else 'not_configured'
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# Error Handlers

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Database Indexes Setup
def setup_database_indexes():
    """Create necessary database indexes for better performance"""
    try:
        # Users collection indexes
        users_collection.create_index('spotify_id', unique=True)
        users_collection.create_index('email')
        users_collection.create_index('username')
        
        # Music data collection indexes
        music_data_collection.create_index('user_id', unique=True)
        
        # Matches collection indexes
        matches_collection.create_index([('user1_id', 1), ('user2_id', 1)], unique=True)
        matches_collection.create_index('user1_id')
        matches_collection.create_index('user2_id')
        matches_collection.create_index('last_interaction')
        matches_collection.create_index('match_score')
        
        logger.info("Database indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error creating database indexes: {str(e)}")

# Application startup
if __name__ == '__main__':
    # Validate environment variables
    if not SPOTIFY_CLIENT_ID or not SPOTIFY_CLIENT_SECRET:
        logger.error("Spotify credentials not found in environment variables")
        exit(1)
    
    # Setup database indexes
    setup_database_indexes()
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )