const mongoose = require('mongoose');

const CommentSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    body: {
        type: String,
        required: true,
    },
    _postId: {
        type: mongoose.Types.ObjectId,
        required: true
    }
    
})

const Comment = mongoose.model('Comment', CommentSchema);

module.exports= { Comment }