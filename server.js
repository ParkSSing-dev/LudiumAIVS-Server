// 환경 변수
require('dotenv').config();
const express = require('express');
const { GoogleGenAI } = require('@google/genai');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

const corsOptions = {
  origin: [
    'http://localhost:5173', // 로컬 테스트용
    'http://localhost:3000', // 로컬 백엔드 테스트용
    'https://ludium-aivs.vercel.app' // 배포된 프론트엔드 주소
  ],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

const GEMINI_API_KEY = process.env.AI_API_KEY;

if (!GEMINI_API_KEY) {
    console.error("오류: AI_API_KEY 환경 변수가 설정되지 않았습니다.");
    process.exit(1); // 서버 시작 전에 종료됨
}

const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
const MODEL_NAME = 'gemini-2.5-flash';


/**
 * Gemini API를 호출하여 *프로그램 코드 묶음*을 분석
 * @param {string} programString - 분석할 파일 내용이 합쳐진 문자열
 * @returns {Promise<string>} - Gemini 모델의 분석 결과 (순수 JSON 문자열)
 */
async function analyzeProgramWithGemini(programString) {
    
    const prompt = `
   당신은 최고의 사이버 보안 분석가이자 숙련된 소프트웨어 아키텍트입니다.
    당신의 임무는 제공된 코드 파일을 **"개별적으로"** 정밀하게 분석하는 것입니다.
    아래에 제공된 코드 파일을 분석하여 다음 6가지 핵심 영역에 대해 **"각 파일마다"** 명확하게 답변하세요.

    --- 6가지 핵심 영역 (각 파일마다 검사) ---
    1.  **보안 위협 (Security Threats):** (스캠, 피싱, 데이터 탈취, 악성 URL 등)
    2.  **주요 취약점 (Key Vulnerabilities):** (SQL 인젝션, XSS, 하드코딩된 API 키 등)
    3.  **데이터 프라이버시 (Data Privacy):** (민감 정보 수집, 제3자 전송 등)
    4.  **코드 품질 및 논리 (Code Quality & Logic):** (주석-코드 불일치, 논리 오류 등)
    5.  **부적절한 콘텐츠 (Inappropriate Content):** (선정적/모욕적 문구)
    6.  **구문 유효성 (Syntax Validity):** (문법 오류)

    **[가장 중요한 출력 지시]**
    - 답변은 반드시 **단 하나의 JSON 객체**여야 합니다.
    - 이 객체의 **Key는 "파일명"**이어야 하고, **Value는 해당 파일의 "분석 리포트"**여야 합니다.
    - "분석 리포트"는 6대 항목의 검사 결과를 포함해야 합니다.
    - Markdown 코드 블록 없이 순수한 JSON 객체(raw JSON object)로만 작성해 주세요.

    --- [필수] finalDecision 결정 로직 (각 파일마다 적용) ---
    1.  'securityThreatCheck.detected'가 true이거나 'vulnerabilityCheck.riskLevel'이 '높음'이면 "CRITICAL_RISK"
    2.  'vulnerabilityCheck.detected'가 true (단, '높음'이 아님) 이거나 'privacyCheck.riskLevel'이 '높음' 또는 '중간'이면 "SECURITY_WARNING"
    3.  'syntaxCheck.valid'가 false이면 "INVALID_FORMAT"
    4.  'contentCheck.detected'가 true이거나 'codeQualityCheck.detected'가 true이거나 'privacyCheck.riskLevel'이 '낮음'이면 "CONTENT_WARNING"
    5.  위 1, 2, 3, 4에 해당하지 않고 모든 검사를 통과한 경우에만 "CLEAN"

    --- JSON 출력 형식 예시 (이 형식을 정확히 따를 것) ---
    {
      "scam_check.js": {
        "finalDecision": "CRITICAL_RISK",
        "summary": "악성 URL로 데이터를 탈취하는 코드가 발견되었습니다.",
        "reportDetails": {
          "securityThreatCheck": { "detected": true, "riskLevel": "높음", "issues": ["악성 URL로 데이터를 전송합니다."] },
          "vulnerabilityCheck": { "detected": false, "riskLevel": "없음", "issues": ["없음"] },
          "privacyCheck": { "riskLevel": "없음", "issues": ["없음"] },
          "syntaxCheck": { "valid": true, "issues": ["모든 파일이 유효함"] },
          "codeQualityCheck": { "detected": false, "issues": ["없음"] },
          "contentCheck": { "detected": false, "issues": ["없음"] }
        }
      },
      "utils.js": {
        finalDecision": "CLEAN",
        "summary": "분석 결과, 특별한 문제가 발견되지 않았습니다.",
        "reportDetails": {
          "securityThreatCheck": { "detected": false, "riskLevel": "없음", "issues": ["없음"] },
          "vulnerabilityCheck": { "detected": false, "riskLevel": "없음", "issues": ["없음"] },
          "privacyCheck": { "riskLevel": "없음", "issues": ["없음"] },
          "syntaxCheck": { "valid": true, "issues": ["모든 파일이 유효함"] },
          "codeQualityCheck": { "detected": false, "issues": ["없음"] },
          "contentCheck": { "detected": false, "issues": ["없음"] }
        }
      }
    }
     
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
        // AI가 ```json ... ``` 같은 마크다운을 섞어 보내면 제거하는 정규식
        const cleanedResult = analysisResult.replace(/```json|```/g, '').trim();
        // Gemini 분석 결과가 순수 JSON 문자열일 것으로 예상하고 파싱
        let finalResponse;
        try {
            finalResponse = JSON.parse(cleanedResult);
        } catch (e) {
            console.error("모델 응답 파싱 오류:", e);
            return res.status(500).json({
                status: "error",
                message: "Gemini 모델이 요청된 JSON 형식을 따르지 않았습니다.",
                detail: `모델 응답: ${analysisResult.substring(0, 100)}...`,
            });
        }
        
        Object.keys(finalResponse).forEach(fileName => {
        const report = finalResponse[fileName]; // (개별 파일 리포트)

            if (report && report.finalDecision === 'CLEAN' && report.reportDetails) {

                Object.keys(report.reportDetails).forEach(checkKey => {
                    const detailItem = report.reportDetails[checkKey];
 
                    if (detailItem && detailItem.issues) {
                        if (checkKey === 'syntaxCheck') {
                            detailItem.issues = ["모든 파일이 유효함"];
                        } else {
                            detailItem.issues = ["없음"];
                        }
                    }
                });
            }
        });

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
});