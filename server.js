// 환경 변수
require('dotenv').config();
const express = require('express');
const { GoogleGenAI } = require('@google/genai');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// --- Gemini API 설정 ---
const GEMINI_API_KEY = process.env.AI_API_KEY;

// .env 파일에 API 키가 없다면 서버 시작 전에 오류를 발생시키고 강제종료임으로 주의하셈!!!!
if (!GEMINI_API_KEY) {
    console.error("오류: AI_API_KEY 환경 변수가 설정되지 않았습니다.");
    process.exit(1); // 서버 시작 전에 종료됨
}

// Gemini api 관련 설정임 건들지 마세요!!
// key 값 하고 모델명 임 
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
const MODEL_NAME = 'gemini-2.5-flash';


/**
 * Gemini API를 호출하여 *프로그램 코드 묶음*을 분석
 * @param {string} programString - 분석할 파일 내용이 합쳐진 문자열
 * @returns {Promise<string>} - Gemini 모델의 분석 결과 (순수 JSON 문자열)
 */
async function analyzeProgramWithGemini(programString) {
    
    const prompt = `
당신은 Snyk, CodeQL처럼 코드의 취약점을 분석하는 고도로 전문화된 'AI 코드 검증 시스템'입니다.
    아래에 제공된 여러 개의 코드 파일을 **"개별적으로"** 분석해야 합니다.

    --- 5대 검증 항목 (각 파일마다) ---
    1.  **[Scam & Security]**: 
        (a) 금융 사기(스캠), 악성 URL 호출, 데이터 탈취 코드
        (b) 심각한 **보안 취약점** (예: SQL 인젝션, XSS, 하드코딩된 API 키)
    2.  **[Validity Check]**: 구문 오류 (문법)
    3.  **[Sensational Check]**: 선정적인 문구 (주석, 변수명)
    4.  **[Data Collection Check]**: 불필요한 민감 정보 수집
    5.  **[Logic Check]**: 논리 오류 (예: 주석과 코드 불일치)

    --- [가장 중요] finalDecision 결정 로직 (필수) ---
    - 답변은 반드시 **단 하나의 JSON 객체**여야 합니다.
    - 이 객체의 **Key는 "파일명"**이어야 하고, **Value는 해당 파일의 "분석 리포트"**여야 합니다.
    - Markdown 코드 블록 없이 순수한 JSON 객체(raw JSON object)로만 작성해 주세요.

    --- 'issues' 배열 출력 규칙 (필수) ---
    - 각 항목의 'issues' 배열에 문제가 없으면, 다른 설명 없이 **정확히** 다음 문자열 중 하나만 반환해야 합니다.
    - 'scamCheck', 'sensationalCheck', 'dataCollectionCheck', 'logicCheck'가 문제 없으면: **["없음"]**
    - 'validityCheck'가 문제 없으면: **["모든 파일이 유효함"]**
    - (AI는 "구문적으로 유효합니다" 같은 다른 표현을 사용해서는 안 됩니다.)
 
    --- JSON 출력 예시 (이 형식을 정확히 따를 것) ---
    {
      "scam_check.js": {
        "finalDecision": "SCAM_DETECTED",
        "summary": "악성 URL로 데이터를 탈취하는 코드가 발견되었습니다.",
        "reportDetails": {
          "scamCheck": { "detected": true, "issues": ["악성 URL(atob(...))로 데이터를 전송합니다."] },
          "validityCheck": { "valid": true, "issues": ["모든 파일이 유효함"] },
          "sensationalCheck": { "detected": false, "issues": ["없음"] },
          "dataCollectionCheck": { "detected": false, "issues": ["없음"] },
          "logicCheck": { "detected": false, "issues": ["없음"] }
        }
      },
      "logic_check.js": {
        "finalDecision": "CONTENT_WARNING",
        "summary": "주석과 실제 코드가 일치하지 않는 논리 오류가 있습니다.",
        "reportDetails": {
          "scamCheck": { "detected": false, "issues": ["없음"] },
          "validityCheck": { "valid": true, "issues": ["모든 파일이 유효함"] },
          "sensationalCheck": { "detected": false, "issues": ["없음"] },
          "dataCollectionCheck": { "detected": false, "issues": ["없음"] },
          "logicCheck": { "detected": true, "issues": ["'calculateFinalPrice' 함수가 주석(할인)과 달리 덧셈을 수행합니다."] }
        }
      },
      "utils.js": {
        "finalDecision": "CLEAN",
        "summary": "분석 결과, 특별한 문제가 발견되지 않았습니다.",
        "reportDetails": {
          "scamCheck": { "detected": false, "issues": ["없음"] },
          "validityCheck": { "valid": true, "issues": ["모든 파일이 유효함"] },
          "sensationalCheck": { "detected": false, "issues": ["없음"] },
          "dataCollectionCheck": { "detected": false, "issues": ["없음"] },
          "logicCheck": { "detected": false, "issues": ["없음"] }
        }
      }
    }4.  위 1, 2, 3에 해당하지 않고 모든 검사를 통과한 경우에만 "CLEAN"
    **AI는 절대로 이 4가지 문자열 외의 값(예: "ERROR", "UNKNOWN")을 'finalDecision'에 반환해서는 안 됩니다.**

    --- [가장 중요] JSON 출력 형식 (필수) ---
    - 답변은 반드시 **단 하나의 JSON 객체**여야 합니다.
    - 이 객체의 **Key는 "파일명"**이어야 하고, **Value는 해당 파일의 "분석 리포트"**여야 합니다.
 
  
    --- 분석할 프로그램 코드 () ---
    ${programString} 
    ---
    `;
    
    try {
        const response = await ai.models.generateContent({
            model: MODEL_NAME,
            contents: prompt,
            config: {
                responseMimeType: 'application/json',
            }
        });
        
        return response.text;
        
    } catch (error) {
        console.error("Gemini API 호출 오류:", error); // 여긴 터미널에 기록되는 메시지
        throw new Error("Gemini API 통신 중 문제가 발생했습니다."); // 여긴 클라이언트에게 전달되는 메시지
    }
}

// --- API 엔드포인트: POST /analyze ---
app.post('/analyze', async (req, res) => {
    
    //프론트엔드가 보낸 'codeFiles' 배열을 추출
    const { programMeta, codeFiles } = req.body;

    // 유효성 검사
    if (!codeFiles || !Array.isArray(codeFiles) || codeFiles.length === 0) {
        return res.status(400).json({ error: "분석할 'codeFiles' 배열이 요청 본문에 포함되어야 합니다." });
    }

    try {
        console.log(`[${new Date().toISOString()}] 요청 데이터 수신:`, req.body.programMeta);
        
        //모든 파일 내용을 하나의 문자열로 합침
        let programContext = `--- 프로그램 제목: ${programMeta.title} ---\n\n`;
        for (const file of codeFiles) {
            programContext += `--- 파일명: ${file.fileName} ---\n`;
            programContext += `${file.content}\n`; // 각 파일의 텍스트 내용
            programContext += `--- 파일 끝: ${file.fileName} ---\n\n`;
        }
        
        //합쳐진 'programContext' 문자열을 분석 함수로 전달
        const analysisResult = await analyzeProgramWithGemini(programContext);
        
        // Gemini 분석 결과가 순수 JSON 문자열일 것으로 예상하고 파싱
        let finalResponse;
        try {
            finalResponse = JSON.parse(analysisResult);
        } catch (e) {
            console.error("모델 응답 파싱 오류:", e);
            return res.status(500).json({
                status: "error",
                message: "Gemini 모델이 요청된 JSON 형식을 따르지 않았습니다.",
                detail: `모델 응답: ${analysisResult.substring(0, 100)}...`,
            });
        }
        
        // 최종적으로 파싱된 JSON 객체를 클라이언트에게 반환
        res.status(200).json({ 
            status: "success",
            analysis: finalResponse 
        });

    } catch (error) {
        console.error(`[${new Date().toISOString()}] 분석 중 서버 오류:`, error.message);// 터미널에 표기됨
        res.status(500).json({ 
            status: "error",
            message: "서버 내부에서 분석을 처리하는 중 오류가 발생했습니다.",// 사용자에게 보여질 메시지
            detail: error.message
        });
    }
});

// --- 서버 시작 --- (문구는 터미널에 표기되므로 신경 쓰지 않아도 되!!)
app.listen(port, () => {
    console.log(`JSON 분석 서버가 http://localhost:${port} 에서 실행 중입니다.`);
    console.log(`분석을 위해 POST 요청을 http://localhost:${port}/analyze 로 보내세요.`);
});