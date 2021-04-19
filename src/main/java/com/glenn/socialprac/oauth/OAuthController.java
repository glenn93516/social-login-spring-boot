package com.glenn.socialprac.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.glenn.socialprac.Member.Member;
import com.glenn.socialprac.Member.MemberDetails;
import com.glenn.socialprac.Member.MemberRepository;
import com.glenn.socialprac.Member.dto.MemberDto;
import com.glenn.socialprac.oauth.dto.GoogleOAuthRequest;
import com.glenn.socialprac.oauth.dto.GoogleOAuthResponse;
import com.glenn.socialprac.utils.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class OAuthController {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    final static String GOOGLE_TOKEN_BASE_URL = "https://oauth2.googleapis.com/token";

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;
    @Value("${redirect-url}")
    private String baseRedirectUrl;


    @GetMapping("/google")
    public ResponseEntity googleAuth(@RequestParam("code") String authorizationCode) throws JsonProcessingException {

        // Resource Server에게 Client 인증
        GoogleOAuthRequest googleOAuthRequestParam = GoogleOAuthRequest.builder()
                .clientId(clientId)
                .clientSecret(clientSecret)
                .code(authorizationCode)
                .redirectUri(baseRedirectUrl + "/google")
                .grantType("authorization_code")
                .build();

        RestTemplate restTemplate = new RestTemplate();

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        // Access token 발급
        ResponseEntity<String> resultEntity = restTemplate.postForEntity(GOOGLE_TOKEN_BASE_URL, googleOAuthRequestParam, String.class);
        System.out.println(resultEntity.getBody());

        GoogleOAuthResponse result = objectMapper.readValue(resultEntity.getBody(), new TypeReference<GoogleOAuthResponse>() {});

        // 유저 정보 획득
        String jwtToken = result.getIdToken();
        String requestUrl = UriComponentsBuilder
                .fromHttpUrl("https://oauth2.googleapis.com/tokeninfo")
                .queryParam("id_token", jwtToken).encode().toUriString();

        String resultJson = restTemplate.getForObject(requestUrl, String.class);

        Map<String,String> userInfo = objectMapper.readValue(resultJson, new TypeReference<Map<String, String>>(){});

        Member member = getMember(userInfo);
        MemberDetails memberDetails = new MemberDetails(member);
        String token = jwtTokenProvider.createToken(member.getId(), memberDetails.getAuthorities());

        return ResponseEntity.status(HttpStatus.OK).body(memberDetails);
    }

    private Member getMember(Map<String, String> userInfo) {
        String email = userInfo.get("email");
        String name = userInfo.get("name");
        String img = userInfo.get("picture");

        MemberDto memberDto = MemberDto.builder()
                .email(email)
                .name(name)
                .img(img)
                .build();

        Member member = memberRepository.findByEmail(email)
                .map(m -> m.updateInfo(m.getName(), m.getImg()))
                .orElse(memberDto.toMember());

        return memberRepository.save(member);
    }

}
