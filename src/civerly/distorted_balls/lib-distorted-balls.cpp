/* This program combines three methods for finding equations describing Sboxes :
    1. Precu method
    2. Distorded balls of radius d = 3, 2, 1
    3. Concatenation of 3 distorded balls
 */

// Note: data types are chosen such that s-boxes can be up to 16 bits, but memory might be a problem for such sizes

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <array>

#define DEBUG 0
#define MAX_RADIUS 4 // upper bound for the radius of the balls used in algorithm 2 and proposition 3

int total_size; // bit length of point (input_size + output_size + prob_encode_bits)
uint64_t n_total; //pow(2, total_size)

class indicator_set{
    public:
        std::vector<uint64_t> indicators;

        indicator_set(){
            indicators = std::vector<uint64_t>(1<<(total_size - 6), 0); // we  can store 6 bits per uint64_t
        }

        void clean(){
            indicators = std::vector<uint64_t>(1<<(total_size - 6), 0);
        }

        bool operator==(const indicator_set& other) const{
            for(int i = 0; i < this->indicators.size(); i++){
                if(other.indicators[i] != this->indicators[i]) return false;
            }
            return true;
        }

        indicator_set operator|(const indicator_set& other) const{
            indicator_set ret;
            for(int i = 0; i < this->indicators.size(); i++){
                ret.indicators[i] = other.indicators[i] | this->indicators[i];
            }
            return ret;
        }

        indicator_set operator&(const indicator_set& other) const{
            indicator_set ret;
            for(int i = 0; i < this->indicators.size(); i++){
                ret.indicators[i] = other.indicators[i] & this->indicators[i];
            }
            return ret;
        }

        void add(uint32_t element){
            indicators[element/64] |= uint64_t(1)<<(element%64);
        }

        void remove(uint32_t element){
            indicators[element/64] &= ~(uint64_t(1)<<(element%64));
        }

        bool contains(uint32_t element){
            return (indicators[element/64] >> (element%64)) & 1;
        }

        bool is_subset_of(const indicator_set& other){
            for(int i = 0; i < indicators.size(); i++){
                if(((~other.indicators[i]) & indicators[i]) != 0) return false;
            }
            return true;
        }
};

struct inequation{
    indicator_set removes_points; // the points this inequation removed
    std::vector<int8_t> coefficients; // the coefficients representing this inequaiton

    inequation(){
        coefficients = std::vector<int8_t>(total_size + 1, 0);
    }
};

indicator_set track; //Table keeping points that have been already treated
std::vector<inequation> inequations; // Stores all inequations produced
std::vector<std::vector<uint32_t>> balls_of_radius;
indicator_set possible_points_ind;
std::vector<uint32_t> impossible_points; // calligraphic P in the paper

static void die(const char* msg){
    perror(msg);
    exit(EXIT_FAILURE);
}

/*
 * Computes the hamming weight of point
 */
int hw(uint32_t point){
    int w = 0;
    for(int i = 0; i < total_size; ++i){
        w += ((point >> i) & 1);
    }
    return w;
}

/*
 * Checks whether p is a possible point
 */
bool is_impossible(uint32_t p){
    return !possible_points_ind.contains(p);
}

/*
 * Computes "set" of impossible points (calligraphic P in the paper)
 */
void compute_impossible_points(){
    if (is_impossible(0))
        impossible_points.push_back(0);
    for (uint32_t el = 1; el < n_total && el != 0; el++) {
        if (is_impossible(el))
            impossible_points.push_back(el);
    }
}

#if DEBUG == 1
/*
 * Prints inequation e
 */
void print_equation(int e){
    for(auto coef: inequations[e].coefficients){
        printf("%2d, ", coef);
    }
    printf("\n");

    for(uint64_t i = 0; i < n_total; i++){
        if(inequations[e].removes_points.contains(i) && !is_impossible(i))
            die("\nERROR: One of the sets of impossible points contains a possible one!\n");
    }
}
#endif

/*
 * Removes redundant inequations by searching for supersets in the forward/backward direction of removes_points
 * Note: it might be possible to make this more efficient by sorting inequations in some way (e.g. by hamming weight)
 * Input:
 *      forward: Whether to clean in the forward or backward direction
 */
void clean_table(bool forward){
    std::vector<inequation> inequations_tmp;

    for(int i = 0; i < inequations.size(); ++i){
#if DEBUG == 1
        if((i % 10000) == 0) printf("i = %d\n",i);
#endif
        bool keep = true;
        if(forward){ // clean in the forward direction
            for (int j = i + 1; j < inequations.size(); j++) {
                if (inequations[i].removes_points.is_subset_of(inequations[j].removes_points)) {
                    keep = false;
                    break;
                }
            }
        }
        else{ // clean in the backward direction
            for(int j = i-1; j >= 0; j--){
                if (inequations[i].removes_points.is_subset_of(inequations[j].removes_points)) {
                    keep = false;
                    break;
                }
            }
        }
        if(keep) // Only keep ones for which no super-set is found
            inequations_tmp.push_back(inequations[i]);
    }
    inequations.swap(inequations_tmp);

#if DEBUG == 1
    printf("Counter after cleaning = %d\n", inequations.size());
#endif
}

/*
 * Initializes the array balls_of_radius. balls_of_radius[d] will contain all elements of hamming-weight at most d.
 */
void compute_balls(){
    for(int d = 0; d < MAX_RADIUS; d++){
        std::vector<uint32_t> ball;
        ball.push_back(0);
        for(uint32_t i = 1; i < n_total && i != 0; i++){  // n_total can be up to pow(2, 32)
            if(hw(i) <= d){
                ball.push_back(i);
            }
        }
        balls_of_radius.push_back(ball);
    }
}

/*
 * Computes the predecessors of p of weight hw(p)-1
 */
std::vector<uint32_t> prec(uint32_t p){
    std::vector<uint32_t> prec_p;

    for(int i=0; i<total_size; i++){
        if (((p >> i) & 1) == 1){
            prec_p.push_back(p ^ (1U << i));
        }
    }
    return std::move(prec_p);
}

/*
 * Checks whether the "set" T1 is a subset of the "set" T2
 */
bool is_included(std::vector<uint32_t> T1, std::vector<uint32_t> T2){
    for(uint32_t i: T1){
        bool inT2 = false;
        for(uint32_t j: T2){
            if(i == j){
                inT2 = true;
                break;
            }
        }
        if(!inT2) return false;
    }
    return true;
}

/*
 * Adds inequation corresponding to a + Prec(u) to inequations (see proposition 1)
 */
void save_inequation(uint32_t a, uint32_t u, int k){
    inequation ineq;
#if DEBUG == 1
    bool print_out = ((inequations.size())%5000) == 0;
#endif

    uint32_t indicator_I = ~(u|a); //the support of indicator_I is I as in proposition 1

    //Compute coefficients of inequation as in proposition 1
    for(int i = 0; i < total_size; i++){
        if((a >> i) & 1) // i-th bit in a in 1
            ineq.coefficients[i] = -1;
        else if((indicator_I >> i) & 1) // i is in I
            ineq.coefficients[i] = 1;
    }

    ineq.coefficients[total_size] = 1 - hw(a); //right-hand side of inequation

    //Compute indicator function of a + Prec(u)
    uint32_t b; //temp variable representing an element of a + Prec(u)
    uint32_t u_comp = ~u; // complement of u
    ineq.removes_points.add(a);
    if(k > total_size/2 && !track.contains(a))
        track.add(a);
    for(uint32_t el=1; el < n_total && el != 0; el++){
        if(u_comp & el) // el is not a predecessor of u
            continue;
        b = a ^ el;
        ineq.removes_points.add(b);
#if DEBUG == 1
        if(print_out) printf("[%d] ", b);
#endif
        if(k > total_size/2 && !track.contains(b))
            track.add(b);
    }
    inequations.push_back(ineq);
#if DEBUG == 1
    if(print_out){
        printf("\nEquation\n");
        print_equation(inequations.size()-1);
    }
#endif
}

/*
 * This function represents the Prec(u) algorithm (algorithm 2 in https://doi.org/10.13154/tosc.v2020.i3.327-361).
 * The result (S_out) will be stored in C and E. Here, C[i] is the indicator-function of the i-th element in S_out
 * and E[i] contains the corresponding coefficients of the inequality given in proposition 1
 */
void algorithm_2(){
    std::vector<std::vector<uint32_t>> U(total_size + 1, std::vector<uint32_t>()); // U[i] represents the set U_i
    std::vector<std::vector<uint32_t>> S(total_size + 1, std::vector<uint32_t>()); // S[i][j] = u such that a + Prec(u) is the j-th element of S_i
    std::vector<uint32_t> prec_u; //Represents the set Prec(u)
    int cleaning_counter = 0; // removing elements (line 27) is done in chunks here

    for(uint32_t a: impossible_points){ // line 3
        for(int i = 0; i < total_size + 1; i++){ // line 5
            S[i].clear(); // line 6
            U[i].clear(); // line 7
        }
        for(uint32_t p: impossible_points){ // line 9
            uint32_t u = a ^ p; // line 10
            if((a & u) == 0){ // line 11
                U[hw(u)].push_back(u); // line 12
            }
        }

        // If we want to be true to the pseudocode we need to uncomment what follows. If we want to get the same results as with the code we got we should leave it as is.
        /*if(U[1].size() == 0){ // line 15
            for(uint32_t u: U[0]){
                //if((inequations.size()%5000) == 0)
                //    printf("%d. 1. : 0x%x + Prec(0x%x)\n", inequations.size(), a, u);
                save_inequation(a, u, 1); // cf. line 16
                cleaning_counter++;
            }
        }
        else{*/
            for(uint32_t u: U[1]){
#if DEBUG == 1
                if((inequations.size()%5000) == 0)
                    printf("%d. 1. : 0x%x + Prec(0x%x)\n", inequations.size(), a, u);
#endif
                save_inequation(a, u, 1); // cf line 18
                cleaning_counter++;
            }
        //}

        for(uint32_t u: U[0]){
            S[0].push_back(u); // line 20
        }
        for(uint32_t u: U[1]){
            S[1].push_back(u);  // line 21
        }

        for(int k = 2; k < total_size + 1; k++){ //line 22
            for(uint32_t u: U[k]){ //line 23
                prec_u = prec(u); //first part of line 24
                if(is_included(prec_u, S[k - 1])){ //second part of line 24
                    S[k].push_back(u); // line 25
#if DEBUG == 1
                    if((inequations.size()%5000) == 0)
                        printf("%d. %d. : 0x%x + Prec(0x%x)\n", inequations.size(), k, a, u);
#endif
                    save_inequation(a, u, k); // cf. line 31 & 33
                    cleaning_counter++;
                    if((cleaning_counter%50000) == 0){ // cf. line 27
                        if((cleaning_counter%100000) == 0) clean_table(false);
                        else clean_table(true);
                    }
                }
            }
        }
    }

    clean_table(true);
    clean_table(false);
}

/*
 * This function represents the algorithm using distorted balls of radius d = 3, 2, 1
 * (see proposition 3 from https://doi.org/10.13154/tosc.v2020.i3.327-361)
 */
void distorted_balls(){
    std::vector<uint32_t> possible_on_sphere; // points on the sphere that need to be removed from the ball
    uint32_t q; // represents q in \mathcal{Q}= (c + Prec(q)) \cap S(d,c) in proposition 3
    inequation ineq;

    for(int d = 3; d>0; d--){
#if DEBUG == 1
        printf("d = %d\n\n", d);
#endif
        for(uint32_t c: impossible_points){ // c in (c + Prec(q)) \cap S(d,c)
            //Construct and check all points in the ball or radius d
            possible_on_sphere.clear();
            bool fits = true;
            for(uint32_t b: balls_of_radius[d]){
                uint32_t new_point = c ^ b;
                if(!is_impossible(new_point)){
                    if(hw(b) != d){ // Possible point, but not on sphere
                        fits = false;
                        break;
                    }
                    possible_on_sphere.push_back(new_point);
                }
            }
            if(!fits) continue; // we are interested in distorted balls that are sub-sets of impossible propagations
            q = 0;
            for(uint32_t j: possible_on_sphere){
                q |= j ^ c;
            }

            ineq = inequation();
            bool correct_form = true; // whether Q is of the form (c + Prec(q)) \cap S(d,c)
            for(uint32_t b: balls_of_radius[d]){
                uint32_t new_point = c ^ b;
                bool is_predecessor = ((new_point & q) == new_point);
                if(!is_predecessor){
                    ineq.removes_points.add(new_point);
                    if(!is_impossible(new_point)){
                        correct_form = false;
                        break;
                    }
                }
                if(is_predecessor && (hw(b) < d)){
                    ineq.removes_points.add(new_point);
                }
            }
            if(correct_form){
                // Constructs the inequation from proposition 3 (multiplied with d), where Q = (c + Prec(q)) \cap S(d,c)
                // Calculate constant of left-hand side
                int const_lhs = 0;
                for(int j = 0; j < total_size; j++){
                    if(((c >> j) & 1) == 1){
                        if(((q >> j) & 1) == 1)
                            const_lhs += (d + 1);
                        else
                            const_lhs += d;
                    }
                }
                // Calculate d*a_i
                for(int j = 0; j < total_size; j++){
                    if(((q >> j) & 1) == 1)
                        ineq.coefficients[j] = d + 1;
                    else
                        ineq.coefficients[j] = d;
                }
                // Compute sign (based on c_i)
                for(int j = 0; j < total_size; j++) {
                    if (((c >> j) & 1) == 1)
                        ineq.coefficients[j] = -ineq.coefficients[j];
                }
                // Move constant from left-hand side to right-hand side
                ineq.coefficients[total_size] = d * (d + 1) - const_lhs;
                // Save equation
                inequations.push_back(ineq);
#if DEBUG == 1
                print_equation(inequations.size()-1);
#endif
            }
        }
    }

    clean_table(true);
    clean_table(false);
}

/*
 * Find the highest bit in value set to 1, assuming that value < (1ULL<<total_size)
 */
int highest_non_zero_bit(uint32_t value){
    if(value == 0)
        return -1;
    for(int t = total_size - 1; t >= 0; t--){
        if((value >> t) == 1) {
            return t;
        }
    }
    die("ERROR: No bit is set, but value is also non-zero"); // We should never get here
    return -2;
}

/*
 * This function merges balls with radius 1 (algorithm 3 in https://doi.org/10.13154/tosc.v2020.i3.327-361)
 */
void merge_balls(){
    int cleaning_counter = 0;
    std::vector<std::vector<uint32_t>> distance_max_one_points(n_total, std::vector<uint32_t>());
    std::array<indicator_set, 3> removed_by_ball;
    inequation ineq;

    int8_t** Eq;
    Eq = (int8_t**)malloc(3*sizeof(int8_t*));
    for(int i = 0; i<3; i++){
        Eq[i] = (int8_t*)calloc((total_size + 1),sizeof(int8_t));
    }

    uint32_t** CL3;
    CL3 = (uint32_t**)malloc(3*sizeof(uint32_t*));
    for(int i = 0; i<3; i++){
        CL3[i] = (uint32_t*)calloc(total_size, sizeof(uint32_t));
    }

    for(uint32_t p1: impossible_points){
        ineq = inequation();
        for(int i = 0; i < total_size; i++){
            if(((p1 >> i) & 1) == 1)
                ineq.coefficients[i] = -1;
            else
                ineq.coefficients[i] = 1;
        }

        //Construct and check all points in the ball
        for(uint32_t b: balls_of_radius[1]){
            uint32_t new_point = p1 ^ b;
            if(is_impossible(new_point)){
                ineq.removes_points.add(new_point);
                distance_max_one_points[p1].push_back(new_point);
            }
            else{
                // (we know that b != 0)
                ineq.coefficients[highest_non_zero_bit(b)] *= 2;
            }
        }
        int count = 0;
        for(int i = 0; i < total_size; i++){
            if(ineq.coefficients[i] < 0) count += ineq.coefficients[i];
        }
        ineq.coefficients[total_size] = 2 + count;
        inequations.push_back(ineq);
        cleaning_counter++;
        if((cleaning_counter%50000) == 0){
            if((cleaning_counter%100000) == 0) clean_table(false);
            else clean_table(true);
        }
#if DEBUG == 1
        if(((inequations.size()-1)%5000) == 0)
            print_equation(inequations.size()-1);
#endif
    }
#if DEBUG == 1
    printf("\nEnd of first part of Method 3\n\n");
#endif
    /* Second step: Add all distorted balls of radius three */
    for(uint32_t p1: impossible_points){ // p1 is the center of the first ball
        if(track.contains(p1))
            continue;
        // Searching for the second ball to consider
        for(uint32_t p2: distance_max_one_points[p1]){ // p2 is the center of the second ball
            if(p2 == p1)
                continue;
            //Searching for the third ball to consider
            for(uint32_t p3: distance_max_one_points[p1]){// p3 is the center of the third ball
                if((p3 == p1) || (p3 == p2))
                    continue;

                for(int i = 0; i < 3; i++)
                    removed_by_ball[i].clean();

                for(uint32_t point: distance_max_one_points[p1])
                    removed_by_ball[0].add(point);
                for(uint32_t point: distance_max_one_points[p2])
                    removed_by_ball[1].add(point);
                for(uint32_t point: distance_max_one_points[p3])
                    removed_by_ball[2].add(point);

                // Adding points to the complementary list of p1
                int cl1 = 0;
                for(uint32_t b : balls_of_radius[1]){
                    uint32_t point = p1 ^ b;
                    if(!is_impossible(point)){
                        CL3[0][cl1] = point;
                        cl1++;
                    }
                }

                // Adding points to the complementary list of p2
                int cl2 = 0;
                for(uint32_t b : balls_of_radius[1]){
                    uint32_t point = p2 ^ b;
                    if(!is_impossible(point)){
                        CL3[1][cl2] = point;
                        cl2++;
                    }
                }

                // Adding points to the complementary list of p3
                int cl3 = 0;
                for(uint32_t b : balls_of_radius[1]){
                    uint32_t point = p3 ^ b;
                    if(!is_impossible(point)){
                        CL3[2][cl3] = point;
                        cl3++;
                    }
                }

                int v = 1;
                for(int u = 0; u<cl2; u++){
                    for(int f = 0; f<cl3; f++){
                        if(CL3[1][u] == CL3[2][f]) v = 0;
                    }
                }
                if(v == 1){
                    // Start removing needed points from these two balls
                    for(int k = 0; k<cl1; k++){
                        uint32_t point = CL3[0][k] ^ p1 ^ p2;
                        if(hw(point ^ p2) == 1){
                            removed_by_ball[1].remove(point);
                        }
                        point = CL3[0][k] ^ p1 ^ p3;
                        if(hw(point ^ p3) == 1){
                            removed_by_ball[2].remove(point);
                        }
                    }
                    for(int k = 0; k<cl2; k++){
                        uint32_t point = CL3[1][k] ^ p2 ^ p3;
                        if(hw(point ^ p3) == 1){
                            removed_by_ball[2].remove(point);
                        }
                    }

                    // construct and add the new inequations for the two distorted balls
                    ineq = inequation();
                    ineq.removes_points = removed_by_ball[0] | removed_by_ball[1] | removed_by_ball[2]; // Removes the union

                    /* Create equations */
                    for(int k = 0; k < total_size; k++){
                        if(((p1 >> k) & 1) == 1) Eq[0][k] = -1;
                        else Eq[0][k] = 1;
                        if(((p2 >> k) & 1) == 1) Eq[1][k] = -1;
                        else Eq[1][k] = 1;
                        if(((p3 >> k) & 1) == 1) Eq[2][k] = -1;
                        else Eq[2][k] = 1;
                    }

                    for(uint32_t b: balls_of_radius[1]){
                        int highest_bit = highest_non_zero_bit(b);
                        // Note: b == 0 implies !removed_by_ball[i].contains(p1 ^ b) == False,
                        // since p1 is always contained in removed_by_ball[i]
                        if(!removed_by_ball[0].contains(p1 ^ b))
                            Eq[0][highest_bit] *= 2;
                        if(!removed_by_ball[1].contains(p2 ^ b))
                            Eq[1][highest_bit] *= 2;
                        if(!removed_by_ball[2].contains(p3 ^ b))
                            Eq[2][highest_bit] *= 2;
                    }

                    // Removing center of the third ball from the first equation.
                    Eq[0][highest_non_zero_bit(p1 ^ p3)] *= 2;

                    for(int k = 0; k < total_size; k++){
                        Eq[2][k] += Eq[0][k] + Eq[1][k];
                    }

                    int count = 0;
                    for(int k = 0; k < total_size; k++){
                        if(Eq[2][k] < 0) count += Eq[2][k];
                        ineq.coefficients[k] = Eq[2][k];
                    }
                    ineq.coefficients[total_size] = 6 + count;
                    inequations.push_back(ineq);
#if DEBUG == 1
                    if(((inequations.size()-1) % 5000) == 0){
                        printf("*** ");
                        print_equation(inequations.size()-1);
                    }
#endif
                    cleaning_counter++;
                    if((cleaning_counter%50000) == 0){
                        if((cleaning_counter%100000) == 0) clean_table(false);
                        else clean_table(true);
                    }
                }
            }
        }
    }

    clean_table(true);
    clean_table(false);

    // Free stuff
    for(int i = 0; i<3; i++){
        free(Eq[i]);
    }
    free(Eq);
    for(int i = 0; i<3; i++){
        removed_by_ball[i].clean();
    }
    for(int i = 0; i<3; i++){
        free(CL3[i]);
    }
    free(CL3);
}

/*
 * Interface accessible from python using ctypes
 */
extern "C" {
    /*
     * Computes inequations for modeling the DDT/LAT given a set of impossible transitions using the method of Boura and Coggia
     *
     * Input:
     *      - bit_length: bit-length of points in possible_points_ind
     *      - possible_points_ind: points representing possible transitions in the DDT/LAT, i.e., DDT[a][b] > 0 iff (a<<in_size)^b in possible_points_ind
     *      - n_possible: number of possible transitions, i.e., the size of possible_points_ind
     *
     * Output:
     *      - Two-dimensional array containing the in-equations. All arrays are null-terminated.
     */
    __attribute__((visibility("default"))) int8_t** compute_inequations(int bit_length, uint32_t* possible_points, int n_possible) {
        if(bit_length < 0 || bit_length > 32) die("ERROR: Bit length out of bounds (maximal supported total length is 32)!");
        total_size = bit_length;

        n_total = 1ULL << total_size;

        for(int i = 0; i < n_possible; i++){
            possible_points_ind.add(possible_points[i]);
        }

        compute_impossible_points();
        /* Main program: Precu (algorithm 2)*/
        algorithm_2();
#if DEBUG == 1
        printf("End of first method. Counter after cleaning = %d\n", inequations.size());
        for(int i = 0; i<inequations.size(); ++i){
            print_equation(i);
        }
#endif
        /* Second method : Simple distorted balls with radius d*/
        compute_balls(); //Precompute masks
#if DEBUG == 1
        printf("Starting of second method\n\n");
#endif
        distorted_balls(); //Starting main program of the second method
#if DEBUG == 1
        printf("\nStarting Third method\n\n");
#endif
        /*Third method: Merge 3 distorted balls */
        merge_balls(); //Starting main program: go through all balls of radius 1
#if DEBUG == 1
        printf("\nEnd of Third method\n\n");
#endif

        // Convert to C array and return
        int8_t** ineqs = (int8_t**)malloc((inequations.size() + 1) * sizeof(int8_t *)); // We add an all-zero line to indicate the end of the array
        for(int i = 0; i < inequations.size(); i++){
            ineqs[i] = (int8_t*)calloc(total_size + 1, sizeof(int8_t));
            for(int j = 0; j < total_size + 1; j++)
                ineqs[i][j] = inequations[i].coefficients[j];
        }
        // Add all-zero line (this corresponds to the inequation 0 >= 0 and should therefore never appear)
        ineqs[inequations.size()] = (int8_t*)calloc(total_size + 1, sizeof(int8_t));
#if DEBUG == 1
        printf("\nReady to return\n\n");
#endif
        // Delete content of global variables
        track.clean();
        inequations.clear();
        balls_of_radius.clear();
        possible_points_ind.clean();
        impossible_points.clear();
        return ineqs;
    }
}




