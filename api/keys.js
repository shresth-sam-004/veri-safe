export default function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(200).json({
        gemini: process.env.GEMINI_API_KEY || '',
        groq: process.env.GROQ_API_KEY || ''
    });
}
