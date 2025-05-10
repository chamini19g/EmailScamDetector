// Import necessary libraries
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Email Scam Detector - A system to identify potential scam emails
 */
class EmailScamDetector {
    // Common scam keywords and phrases
    private static final List<String> SCAM_KEYWORDS = Arrays.asList(
        "urgent", "million dollars", "lottery", "winner", "inheritance", 
        "bank transfer", "foreign prince", "claim your prize", "wire transfer",
        "confidential", "business proposal", "investment opportunity", "unclaimed",
        "congratulations", "lucky winner", "offshore", "account details"
    );
    
    // Suspicious patterns (URLs, account numbers, etc.)
    private static final List<Pattern> SUSPICIOUS_PATTERNS = Arrays.asList(
        // Suspicious URLs that don't match common domains
        Pattern.compile("https?://(?!www\\.(google|yahoo|microsoft|apple|amazon)\\.com)[^\\s]+"),
        // Requests for bank details
        Pattern.compile("bank\\s+(?:account|details|information|routing)", Pattern.CASE_INSENSITIVE),
        // Requests for personal information
        Pattern.compile("send\\s+(?:your|ur)\\s+(?:password|credit card|ssn|social security)", Pattern.CASE_INSENSITIVE)
    );
    
    // Weights for different features
    private static final Map<String, Double> FEATURE_WEIGHTS = new HashMap<>();
    static {
        FEATURE_WEIGHTS.put("scamKeywords", 0.4);
        FEATURE_WEIGHTS.put("suspiciousPatterns", 0.3);
        FEATURE_WEIGHTS.put("urgencyLevel", 0.2);
        FEATURE_WEIGHTS.put("poorGrammar", 0.1);
    }
    
    /**
     * Analyzes an email and returns a scam probability score
     * @param subject Email subject
     * @param body Email body
     * @param sender Email sender
     * @return A score between 0 and 1, where higher values indicate higher scam probability
     */
    public static double analyzeEmail(String subject, String body, String sender) {
        // Combine subject and body for analysis
        String fullText = subject + " " + body;
        fullText = fullText.toLowerCase();
        
        // Calculate individual feature scores
        double keywordScore = calculateKeywordScore(fullText);
        double patternScore = calculatePatternScore(fullText);
        double urgencyScore = calculateUrgencyScore(fullText);
        double grammarScore = calculateGrammarScore(fullText);
        
        // Calculate weighted score
        double weightedScore = 
            keywordScore * FEATURE_WEIGHTS.get("scamKeywords") +
            patternScore * FEATURE_WEIGHTS.get("suspiciousPatterns") +
            urgencyScore * FEATURE_WEIGHTS.get("urgencyLevel") +
            grammarScore * FEATURE_WEIGHTS.get("poorGrammar");
        
        // Normalize score to be between 0 and 1
        return Math.min(1.0, weightedScore);
    }
    
    /**
     * Calculates a score based on presence of scam keywords
     */
    private static double calculateKeywordScore(String text) {
        int matches = 0;
        for (String keyword : SCAM_KEYWORDS) {
            if (text.contains(keyword.toLowerCase())) {
                matches++;
            }
        }
        
        // Normalize by the number of keywords
        return (double) matches / SCAM_KEYWORDS.size() * 2.0;
    }
    
    /**
     * Calculates a score based on suspicious patterns
     */
    private static double calculatePatternScore(String text) {
        int matches = 0;
        for (Pattern pattern : SUSPICIOUS_PATTERNS) {
            Matcher matcher = pattern.matcher(text);
            if (matcher.find()) {
                matches++;
            }
        }
        
        // Normalize by the number of patterns
        return (double) matches / SUSPICIOUS_PATTERNS.size() * 2.0;
    }
    
    /**
     * Calculates a score based on urgency indicators
     */
    private static double calculateUrgencyScore(String text) {
        List<String> urgencyPhrases = Arrays.asList(
            "urgent", "immediate", "act now", "limited time", "expires soon",
            "today only", "last chance", "deadline", "quickly", "hurry"
        );
        
        int matches = 0;
        for (String phrase : urgencyPhrases) {
            if (text.contains(phrase)) {
                matches++;
            }
        }
        
        return (double) matches / urgencyPhrases.size() * 2.0;
    }
    
    /**
     * Calculates a score based on grammar and spelling issues
     * This is a simplified implementation - a real system would use NLP libraries
     */
    private static double calculateGrammarScore(String text) {
        // Simple heuristics for poor grammar
        int issues = 0;
        
        // Check for ALL CAPS sections
        if (text.replaceAll("[^A-Z]", "").length() > 20) {
            issues++;
        }
        
        // Check for excessive punctuation
        if (text.replaceAll("[^!]", "").length() > 5) {
            issues++;
        }
        
        // Check for common grammar mistakes
        List<String> grammarMistakes = Arrays.asList(
            "your the", "you is", "we is", "they is", "i is",
            "kindly do the needful", "revert back", "please to"
        );
        
        for (String mistake : grammarMistakes) {
            if (text.contains(mistake)) {
                issues++;
            }
        }
        
        return Math.min(1.0, issues / 5.0);
    }
    
    /**
     * Classifies an email as safe, suspicious, or dangerous based on score
     */
    public static String classifyEmail(double score) {
        if (score < 0.3) {
            return "SAFE";
        } else if (score < 0.7) {
            return "SUSPICIOUS";
        } else {
            return "DANGEROUS";
        }
    }
    
    /**
     * Provides detailed analysis of why an email might be suspicious
     */
    public static List<String> getScamIndicators(String subject, String body, String sender) {
        List<String> indicators = new ArrayList<>();
        String fullText = (subject + " " + body).toLowerCase();
        
        // Check for scam keywords
        for (String keyword : SCAM_KEYWORDS) {
            if (fullText.contains(keyword.toLowerCase())) {
                indicators.add("Contains suspicious keyword: " + keyword);
            }
        }
        
        // Check for suspicious patterns
        for (Pattern pattern : SUSPICIOUS_PATTERNS) {
            Matcher matcher = pattern.matcher(fullText);
            if (matcher.find()) {
                indicators.add("Contains suspicious pattern: " + matcher.group());
            }
        }
        
        // Check sender domain
        if (!sender.matches(".*@(gmail|yahoo|outlook|hotmail|aol)\\.com$")) {
            indicators.add("Sender domain may be suspicious: " + sender);
        }
        
        return indicators;
    }
    
    // Main method for demonstration
    public static void main(String[] args) {
        // Example 1: Legitimate email
        String subject1 = "Team meeting tomorrow";
        String body1 = "Hi team, Just a reminder that we have our weekly meeting tomorrow at 10am. Please prepare your status updates. Thanks, Manager";
        String sender1 = "manager@company.com";
        
        // Example 2: Suspicious email
        String subject2 = "URGENT: Your account needs verification";
        String body2 = "Dear valued customer, We have noticed suspicious activity on your account. Please verify your account by clicking on this link: http://secure-bank-verify.com and enter your account details. Act now to prevent account suspension!";
        String sender2 = "security@bank-secure-verify.com";
        
        // Example 3: Obvious scam
        String subject3 = "CONGRATULATIONS! YOU WON $5,000,000 LOTTERY!!!";
        String body3 = "Dear Lucky Winner, You have been selected to receive $5,000,000 from the International Lottery. To claim your prize, please send your bank account details and a processing fee of $100 via wire transfer to our agent. This is URGENT as your prize will expire in 24 hours! Kindly do the needful.";
        String sender3 = "agent@international-lottery-winner.org";
        
        // Analyze emails
        analyzeAndPrintResults(subject1, body1, sender1, "Example 1 (Legitimate)");
        analyzeAndPrintResults(subject2, body2, sender2, "Example 2 (Suspicious)");
        analyzeAndPrintResults(subject3, body3, sender3, "Example 3 (Scam)");
    }
    
    private static void analyzeAndPrintResults(String subject, String body, String sender, String label) {
        double score = analyzeEmail(subject, body, sender);
        String classification = classifyEmail(score);
        List<String> indicators = getScamIndicators(subject, body, sender);
        
        System.out.println("\n" + label);
        System.out.println("Subject: " + subject);
        System.out.println("From: " + sender);
        System.out.println("Scam probability score: " + String.format("%.2f", score));
        System.out.println("Classification: " + classification);
        
        if (!indicators.isEmpty()) {
            System.out.println("Scam indicators found:");
            for (String indicator : indicators) {
                System.out.println("- " + indicator);
            }
        } else {
            System.out.println("No scam indicators found.");
        }
    }
}

// Run the demonstration
EmailScamDetector.main(null);